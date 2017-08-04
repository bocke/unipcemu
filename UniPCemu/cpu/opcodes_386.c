#include "headers/types.h" //Basic types
#include "headers/cpu/cpu.h" //CPU needed!
#include "headers/cpu/mmu.h" //MMU needed!
#include "headers/cpu/easyregs.h" //Easy register compatibility!
#include "headers/cpu/modrm.h" //MODR/M compatibility!
#include "headers/support/signedness.h" //CPU support functions!
#include "headers/hardware/ports.h" //Ports compatibility!
#include "headers/cpu/cpu_OP8086.h" //Our own opcode presets!
#include "headers/cpu/fpu_OP8087.h" //Our own opcode presets!
#include "headers/cpu/flags.h" //Flag support!
#include "headers/cpu/8086_grpOPs.h" //GRP Opcode extensions!
#include "headers/cpu/interrupts.h" //Basic interrupt support!
#include "headers/emu/debugger/debugger.h" //CPU debugger support!
#include "headers/bios/bios.h" //BIOS support!
#include "headers/cpu/protection.h"
#include "headers/mmu/mmuhandler.h" //MMU_invaddr support!
#include "headers/cpu/cpu_OPNECV30.h" //80186+ support!
#include "headers/cpu/cpu_OP80286.h" //80286+ support!
#include "headers/cpu/biu.h" //BIU support!

MODRM_PARAMS params; //For getting all params for the CPU!
extern byte cpudebugger; //The debugging is on?
extern byte blockREP; //Block the instruction from executing (REP with (E)CX=0

//How many cycles to substract from the documented instruction timings for the raw EU cycles for each BIU access?
#define EU_CYCLES_SUBSTRACT_ACCESSREAD 4
#define EU_CYCLES_SUBSTRACT_ACCESSWRITE 4
#define EU_CYCLES_SUBSTRACT_ACCESSRW 8

//When using http://www.mlsite.net/8086/: G=Modr/m mod&r/m adress, E=Reg field in modr/m

//INFO: http://www.mlsite.net/8086/
//Extra info about above: Extension opcodes (GRP1 etc) are contained in the modr/m
//Ammount of instructions in the completed core: 123

//Aftercount: 60-6F,C0-C1, C8-C9, D6, D8-DF, F1, 0F(has been implemented anyways)
//Total count: 30 opcodes undefined.

//Info: Ap = 32-bit segment:offset pointer (data: param 1:word segment, param 2:word offset)

//Simplifier!

extern uint_32 destEIP; //Destination address for CS JMP instruction!

extern byte immb; //For CPU_readOP result!
extern word immw; //For CPU_readOPw result!
extern uint_32 imm32; //For CPU_readOPdw result!
extern uint_64 imm64; //For CPU_readOPdw result!
extern byte oper1b, oper2b; //Byte variants!
extern word oper1, oper2; //Word variants!
uint_32 oper1d, oper2d; //DWord variants!
extern byte res8; //Result 8-bit!
extern word res16; //Result 16-bit!
uint_32 res32; //Result 32-bit!
extern byte thereg; //For function number!
extern uint_32 ea; //From RM OFfset (GRP5 Opcodes only!)
extern byte tempCF2;

VAL64Splitter temp1, temp2, temp3, temp4, temp5; //All temporary values!
extern uint_32 temp32, tempaddr32; //Defined in opcodes_8086.c

extern byte debuggerINT; //Interrupt special trigger?

extern uint_32 immaddr32; //Immediate address, for instructions requiring it, either 16-bits or 32-bits of immediate data, depending on the address size!

/*

First, 8086 32-bit extensions!

*/

//Prototypes for GRP code extensions!
void op_grp3_32(); //Prototype!
uint_32 op_grp2_32(byte cnt, byte varshift); //Prototype!
void op_grp5_32(); //Prototype

OPTINLINE void INTdebugger80386() //Special INTerrupt debugger!
{
	if (DEBUGGER_LOG==DEBUGGERLOG_INT) //Interrupts only?
	{
		debuggerINT = 1; //Debug this instruction always!
	}
}

/*

Start of help for debugging

*/

extern char modrm_param1[256]; //Contains param/reg1
extern char modrm_param2[256]; //Contains param/reg2

char LEAtext[256];
OPTINLINE char *getLEAtext32(MODRM_PARAMS *theparams)
{
	modrm_lea32_text(theparams,1,&LEAtext[0]);    //Help function for LEA instruction!
	return &LEAtext[0];
}

/*

Start of help for opcode processing

*/

extern byte CPU_databussize; //0=16/32-bit bus! 1=8-bit bus when possible (8088/80188)!
extern uint_32 wordaddress; //Word address used during memory access!

OPTINLINE byte CPU80386_software_int(byte interrupt, int_64 errorcode) //See int, but for hardware interrupts (IRQs)!
{
	return call_soft_inthandler(interrupt,errorcode); //Save adress to stack (We're going soft int!)!
}

OPTINLINE byte CPU80386_INTERNAL_int(byte interrupt, byte type3) //Software interrupt from us(internal call)!
{
	byte result = 1; //Result!
	CPUPROT1
		/*
		if (EMULATED_CPU<=CPU_NECV30) //16-bit CPU?
		{
			result = CPU8086_software_int(interrupt,-1);
			if (result) //Final stage?
			{
				CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /Stall the BIU completely now!/
			}
		}
		else
		*/ //Unsupported CPU? Use plain general interrupt handling instead!
		{
			CPU80386_software_int(interrupt,-1);
			if (CPU_apply286cycles()) return 1; //80286+ cycles instead?
			result = 1; //Always 1!
		}
		return result; //Finished!
	CPUPROT2
	return result; //Finished!
}

void CPU80386_int(byte interrupt) //Software interrupt (external call)!
{
	CPU80386_INTERNAL_int(interrupt,0); //Direct call!
}

OPTINLINE void CPU80386_IRET()
{
	CPUPROT1
	CPU_IRET(); //IRET!
	CPUPROT2
	if (CPU_apply286cycles()) return; //80286+ cycles instead?
	CPU[activeCPU].cycles_OP = 24; /*Timings!*/
}

/*

List of hardware interrupts:
0: Division by 0: Attempting to execute DIV/IDIV with divisor==0: IMPLEMENTED
1: Debug/Single step: Breakpoint hit, also after instruction when TRAP flag is set.
3: Breakpoint: INT 3 call: IMPLEMENTED
4: Overflow: When performing arithmetic instructions with signed operands. Called with INTO.
5: Bounds Check: BOUND instruction exceeds limit.
6: Invalid OPCode: Invalid LOCK prefix or invalid OPCode: IMPLEMENTED
7: Device not available: Attempt to use floating point instruction (8087) with no COProcessor.
8: Double fault: Interrupt occurs with no entry in IVT or exception within exception handler.
12: Stack exception: Stack operation exceeds offset FFFFh or a selector pointing to a non-present segment is loaded into SS.
13: CS,DS,ES,FS,GS Segment Overrun: Word memory access at offset FFFFh or an attempt to execute past the end of the code segment.
16: Floating point error: An error with the numeric coprocessor (Divide-by-Zero, Underflow, Overflow...)

*/


//5 Override prefixes! (LOCK, CS, SS, DS, ES)

//Prefix opcodes:
/*
void CPU80386_OPF0() {} //LOCK
void CPU80386_OP2E() {} //CS:
void CPU80386_OP36() {} //SS:
void CPU80386_OP3E() {} //DS:
void CPU80386_OP26() {} //ES:
void CPU80386_OPF2() {} //REPNZ
void CPU80386_OPF3() {} //REPZ
*/

/*

WE START WITH ALL HELP FUNCTIONS

*/

//First CMP instruction (for debugging) and directly related.

//CMP: Substract and set flags according (Z,S,O,C); Help functions

OPTINLINE void op_adc32() {
	res32 = oper1d + oper2d + FLAG_CF;
	flag_adc32 (oper1d, oper2d, FLAG_CF);
}

OPTINLINE void op_add32() {
	res32 = oper1d + oper2d;
	flag_add32 (oper1d, oper2d);
}

OPTINLINE void op_and32() {
	res32 = oper1d & oper2d;
	flag_log32 (res32);
}

OPTINLINE void op_or32() {
	res32 = oper1d | oper2d;
	flag_log32 (res32);
}

OPTINLINE void op_xor32() {
	res32 = oper1d ^ oper2d;
	flag_log32 (res32);
}

OPTINLINE void op_sub32() {
	res32 = oper1d - oper2d;
	flag_sub32 (oper1d, oper2d);
}

OPTINLINE void op_sbb32() {
	res32 = oper1d - (oper2d + FLAG_CF);
	flag_sbb32 (oper1d, oper2d, FLAG_CF);
}

/*

32-bit versions of BIU operations!

*/

//Stack operation support through the BIU!
byte CPU80386_PUSHdw(byte base, uint_32 *data)
{
	uint_32 temp;
	if (CPU[activeCPU].instructionstep==base) //First step? Request!
	{
		if (CPU_PUSH32_BIU(data)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].instructionstep; //Next step!
	}
	if (CPU[activeCPU].instructionstep==(base+1))
	{
		if (BIU_readResultdw(&temp)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].instructionstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

byte CPU80386_internal_PUSHdw(byte base, uint_32 *data)
{
	uint_32 temp;
	if (CPU[activeCPU].internalinstructionstep==base) //First step? Request!
	{
		if (CPU_PUSH32_BIU(data)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalinstructionstep; //Next step!
	}
	if (CPU[activeCPU].internalinstructionstep==(base+1))
	{
		if (BIU_readResultdw(&temp)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalinstructionstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

byte CPU80386_internal_interruptPUSHdw(byte base, uint_32 *data)
{
	uint_32 temp;
	if (CPU[activeCPU].internalinterruptstep==base) //First step? Request!
	{
		if (CPU_PUSH32_BIU(data)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalinterruptstep; //Next step!
	}
	if (CPU[activeCPU].internalinterruptstep==(base+1))
	{
		if (BIU_readResultdw(&temp)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalinterruptstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

byte CPU80386_POPdw(byte base, uint_32 *result)
{
	if (CPU[activeCPU].instructionstep==base) //First step? Request!
	{
		if (CPU_POP32_BIU()==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].instructionstep; //Next step!
	}
	if (CPU[activeCPU].instructionstep==(base+1))
	{
		if (BIU_readResultdw(result)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].instructionstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

byte CPU80386_internal_POPdw(byte base, uint_32 *result)
{
	if (CPU[activeCPU].internalinstructionstep==base) //First step? Request!
	{
		if (CPU_POP32_BIU()==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalinstructionstep; //Next step!
	}
	if (CPU[activeCPU].internalinstructionstep==(base+1))
	{
		if (BIU_readResultdw(result)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalinstructionstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

byte CPU80386_POPESP(byte base)
{
	if (CPU[activeCPU].instructionstep==base) //First step? Request!
	{
		if (BIU_request_MMUrdw(CPU_SEGMENT_SS,STACK_SEGMENT_DESCRIPTOR_B_BIT?REG_ESP:REG_SP,1)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].instructionstep; //Next step!
	}
	if (CPU[activeCPU].instructionstep==(base+1))
	{
		if (BIU_readResultdw(&REG_ESP)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].instructionstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

//Instruction variants of ModR/M!

byte CPU80386_instructionstepreadmodrmdw(byte base, uint_32 *result, byte paramnr)
{
	byte BIUtype;
	if (CPU[activeCPU].instructionstep==base) //First step? Request!
	{
		if ((BIUtype = modrm_read32_BIU(&params,paramnr,result))==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].instructionstep; //Next step!
		if (BIUtype==2) //Register?
		{
			++CPU[activeCPU].instructionstep; //Skip next step!
		}
	}
	if (CPU[activeCPU].instructionstep==(base+1))
	{
		if (BIU_readResultdw(result)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].instructionstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

byte CPU80386_instructionstepwritemodrmdw(byte base, uint_32 value, byte paramnr)
{
	uint_32 dummy;
	byte BIUtype;
	if (CPU[activeCPU].instructionstep==base) //First step? Request!
	{
		if ((BIUtype = modrm_write32_BIU(&params,paramnr,value))==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].instructionstep; //Next step!
		if (BIUtype==2) //Register?
		{
			++CPU[activeCPU].instructionstep; //Skip next step!
		}
	}
	if (CPU[activeCPU].instructionstep==(base+1))
	{
		if (BIU_readResultdw(&dummy)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].instructionstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

//Now, the internal variants of the functions above!

byte CPU80386_internal_stepreadmodrmdw(byte base, uint_32 *result, byte paramnr)
{
	byte BIUtype;
	if (CPU[activeCPU].internalmodrmstep==base) //First step? Request!
	{
		if ((BIUtype = modrm_read32_BIU(&params,paramnr,result))==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalmodrmstep; //Next step!
		if (BIUtype==2) //Register?
		{
			++CPU[activeCPU].internalmodrmstep; //Skip next step!
		}
	}
	if (CPU[activeCPU].internalmodrmstep==(base+1))
	{
		if (BIU_readResultdw(result)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalmodrmstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

byte CPU80386_internal_stepwritedirectdw(byte base, sword segment, word segval, uint_32 offset, uint_32 val, byte is_offset16)
{
	uint_32 dummy;
	if (CPU[activeCPU].internalmodrmstep==base) //First step? Request!
	{
		if (BIU_request_MMUwdw(segment,offset,val,is_offset16)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalmodrmstep; //Next step!
	}
	if (CPU[activeCPU].internalmodrmstep==(base+1))
	{
		if (BIU_readResultdw(&dummy)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalmodrmstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

byte CPU80386_internal_stepreaddirectdw(byte base, sword segment, word segval, uint_32 offset, uint_32 *result, byte is_offset16)
{
	if (CPU[activeCPU].internalmodrmstep==base) //First step? Request!
	{
		if (BIU_request_MMUrdw(segment,offset,is_offset16)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalmodrmstep; //Next step!
	}
	if (CPU[activeCPU].internalmodrmstep==(base+1))
	{
		if (BIU_readResultdw(result)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalmodrmstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

byte CPU80386_internal_stepreadinterruptdw(byte base, sword segment, word segval, uint_32 offset, uint_32 *result, byte is_offset16)
{
	if (CPU[activeCPU].internalinterruptstep==base) //First step? Request!
	{
		if (BIU_request_MMUrdw(segment,offset,is_offset16)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalinterruptstep; //Next step!
	}
	if (CPU[activeCPU].internalinterruptstep==(base+1))
	{
		if (BIU_readResultdw(result)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalinterruptstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

byte CPU80386_internal_stepwritemodrmdw(byte base, uint_32 value, byte paramnr)
{
	uint_32 dummy;
	byte BIUtype;
	if (CPU[activeCPU].internalmodrmstep==base) //First step? Request!
	{
		if ((BIUtype = modrm_write32_BIU(&params,paramnr,value))==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalmodrmstep; //Next step!
		if (BIUtype==2) //Register?
		{
			++CPU[activeCPU].internalmodrmstep; //Skip next step!
		}
	}
	if (CPU[activeCPU].internalmodrmstep==(base+1))
	{
		if (BIU_readResultdw(&dummy)==0) //Not ready?
		{
			CPU[activeCPU].cycles_OP += 1; //Take 1 cycle only!
			CPU[activeCPU].executed = 0; //Not executed!
			return 1; //Keep running!
		}
		++CPU[activeCPU].internalmodrmstep; //Next step!
	}
	return 0; //Ready to process further! We're loaded!
}

/*

Start of general 80386+ CMP handlers!

*/

OPTINLINE void CMP_dw(uint_32 a, uint_32 b, byte flags) //Compare instruction!
{
	CPUPROT1
	flag_sub32(a,b); //Flags only!
	if (CPU_apply286cycles()) return; //80286+ cycles instead?
	switch (flags & 7)
	{
	case 0: //Default?
		break; //Unused!
	case 1: //Accumulator?
		CPU[activeCPU].cycles_OP += 4; //Imm-Reg
		break;
	case 2: //Determined by ModR/M?
		if (params.EA_cycles) //Memory is used?
		{
			CPU[activeCPU].cycles_OP += 9-EU_CYCLES_SUBSTRACT_ACCESSREAD; //Mem->Reg!
		}
		else //Reg->Reg?
		{
			CPU[activeCPU].cycles_OP += 3; //Reg->Reg!
		}
		break;
	case 3: //ModR/M+imm?
		if (params.EA_cycles) //Memory is used?
		{
			CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSREAD; //Mem->Reg!
		}
		else //Imm->Reg?
		{
			CPU[activeCPU].cycles_OP += 4; //Reg->Reg!
		}
		break;
	case 4: //Mem-Mem instruction?
		CPU[activeCPU].cycles_OP += 18-(EU_CYCLES_SUBSTRACT_ACCESSREAD*2); //Assume two times Reg->Mem
		break;
	}
	CPUPROT2
}

//Modr/m support, used when reg=NULL and custommem==0
extern byte MODRM_src0; //What source is our modr/m? (1/2)
extern byte MODRM_src1; //What source is our modr/m? (1/2)

//Custom memory support!
extern byte custommem ; //Used in some instructions!
extern uint_32 customoffset; //Offset to use!

/*

Start of general 80386+ instruction handlers!

*/

//Help functions:
OPTINLINE byte CPU80386_internal_INC32(uint_32 *reg)
{
	if (MMU_invaddr())
	{
		return 1;
	}
	//Check for exceptions first!
	if (!reg) if (modrm_check32(&params,MODRM_src0,1)) return 1; //Abort on fault!
	if (!reg) if (modrm_check32(&params,MODRM_src0,0)) return 1; //Abort on fault!
	CPUPROT1
	INLINEREGISTER byte tempCF = FLAG_CF; //CF isn't changed!
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (reg==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepreadmodrmdw(0,&oper1d,MODRM_src0)) return 1;
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //Execution step?
	{
		oper1d = reg?*reg:oper1d;
		oper2d = 1;
		op_add32();
		FLAGW_CF(tempCF);
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
		if (reg==NULL) //Destination to write?
		{
			if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
			{
				CPU[activeCPU].cycles_OP += 15-(EU_CYCLES_SUBSTRACT_ACCESSRW); //Mem
			}
			CPU[activeCPU].executed = 0;
			return 1; //Wait for execution phase to finish!
		}
	}
	if (reg) //Register?
	{
		*reg = res32;
		if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
		{
			CPU[activeCPU].cycles_OP += 2; //16-bit reg!
		}
	}
	else //Memory?
	{
		if (reg==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepwritemodrmdw(2,res32,MODRM_src0)) return 1;
		}
	}
	CPUPROT2
	return 0;
}
OPTINLINE byte CPU80386_internal_DEC32(uint_32 *reg)
{
	if (MMU_invaddr())
	{
		return 1;
	}
	if (!reg) if (modrm_check32(&params,MODRM_src0,1)) return 1; //Abort on fault!
	if (!reg) if (modrm_check32(&params,MODRM_src0,0)) return 1; //Abort on fault!
	CPUPROT1
	INLINEREGISTER byte tempCF = FLAG_CF; //CF isn't changed!
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (reg==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepreadmodrmdw(0,&oper1d,MODRM_src0)) return 1;
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //Execution step?
	{
		oper1d = reg?*reg:oper1d;
		oper2d = 1;
		op_sub32();
		FLAGW_CF(tempCF);
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
		if (reg==NULL) //Destination to write?
		{
			if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
			{
				CPU[activeCPU].cycles_OP += 15-(EU_CYCLES_SUBSTRACT_ACCESSRW); //Mem
			}
			CPU[activeCPU].executed = 0;
			return 1; //Wait for execution phase to finish!
		}
	}
	if (reg) //Register?
	{
		*reg = res32;
		if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
		{
			CPU[activeCPU].cycles_OP += 2; //16-bit reg!
		}
	}
	else //Memory?
	{
		if (reg==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepwritemodrmdw(2,res32,MODRM_src0)) return 1;
		}
	}
	CPUPROT2
	return 0;
}

OPTINLINE void timing_AND_OR_XOR_ADD_SUB32(uint_32 *dest, byte flags)
{
	if (CPU_apply286cycles()) return; //No 80286+ cycles instead?
	switch (flags) //What type of operation?
	{
	case 0: //Reg+Reg?
		CPU[activeCPU].cycles_OP += 3; //Reg->Reg!
		break;
	case 1: //Reg+imm?
		CPU[activeCPU].cycles_OP += 4; //Accumulator!
		break;
	case 2: //Determined by ModR/M?
		if (params.EA_cycles) //Memory is used?
		{
			if (dest) //Mem->Reg?
			{
				CPU[activeCPU].cycles_OP += 9-EU_CYCLES_SUBSTRACT_ACCESSREAD; //Mem->Reg!
			}
			else //Reg->Mem?
			{
				CPU[activeCPU].cycles_OP += 16-(EU_CYCLES_SUBSTRACT_ACCESSRW); //Mem->Reg!
			}
		}
		else //Reg->Reg?
		{
			CPU[activeCPU].cycles_OP += 3; //Reg->Reg!
		}
		break;
	case 3: //ModR/M+imm?
		if (params.EA_cycles) //Memory is used?
		{
			if (dest) //Imm->Reg?
			{
				CPU[activeCPU].cycles_OP += 4; //Imm->Reg!
			}
			else //Imm->Mem?
			{
				CPU[activeCPU].cycles_OP += 17-(EU_CYCLES_SUBSTRACT_ACCESSRW); //Mem->Reg!
			}
		}
		else //Reg->Reg?
		{
			CPU[activeCPU].cycles_OP += 3; //Reg->Reg!
		}
		break;
	}
}

//For ADD
OPTINLINE byte CPU80386_internal_ADD32(uint_32 *dest, uint_32 addition, byte flags)
{
	if (MMU_invaddr())
	{
		return 1;
	}
	if (!dest) if (modrm_check32(&params,MODRM_src0,1)) return 1; //Abort on fault!
	if (!dest) if (modrm_check32(&params,MODRM_src0,0)) return 1; //Abort on fault!
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepreadmodrmdw(0,&oper1d,MODRM_src0)) return 1;
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //Execution step?
	{
		oper1d = dest?*dest:oper1d;
		oper2d = addition;
		op_add32();
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
		timing_AND_OR_XOR_ADD_SUB32(dest, flags);
		if (dest==NULL) { CPU[activeCPU].executed = 0; return 1; } //Wait for execution phase to finish!
	}
	if (dest) //Register?
	{
		*dest = res32;
	}
	else //Memory?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepwritemodrmdw(2,res32,MODRM_src0)) return 1;
		}
	}
	CPUPROT2
	return 0;
}

//For ADC
OPTINLINE byte CPU80386_internal_ADC32(uint_32 *dest, uint_32 addition, byte flags)
{
	if (MMU_invaddr())
	{
		return 1;
	}
	if (!dest) if (modrm_check32(&params,MODRM_src0,1)) return 1; //Abort on fault!
	if (!dest) if (modrm_check32(&params,MODRM_src0,0)) return 1; //Abort on fault!
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepreadmodrmdw(0,&oper1d,MODRM_src0)) return 1;
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //Execution step?
	{
		oper1d = dest?*dest:oper1d;
		oper2d = addition;
		op_adc32();
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
		timing_AND_OR_XOR_ADD_SUB32(dest, flags);
		if (dest==NULL) { CPU[activeCPU].executed = 0; return 1; } //Wait for execution phase to finish!
	}
	if (dest) //Register?
	{
		*dest = res32;
	}
	else //Memory?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepwritemodrmdw(2,res32,MODRM_src0)) return 1;
		}
	}
	CPUPROT2
	return 0;
}


//For OR
OPTINLINE byte CPU80386_internal_OR32(uint_32 *dest, uint_32 src, byte flags)
{
	if (MMU_invaddr())
	{
		return 1;
	}
	if (!dest) if (modrm_check32(&params,MODRM_src0,1)) return 1; //Abort on fault!
	if (!dest) if (modrm_check32(&params,MODRM_src0,0)) return 1; //Abort on fault!
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepreadmodrmdw(0,&oper1d,MODRM_src0)) return 1;
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //Execution step?
	{
		oper1d = dest?*dest:oper1d;
		oper2d = src;
		op_or32();
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
		timing_AND_OR_XOR_ADD_SUB32(dest, flags);
		if (dest==NULL) { CPU[activeCPU].executed = 0; return 1; } //Wait for execution phase to finish!
	}
	if (dest) //Register?
	{
		*dest = res32;
	}
	else //Memory?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepwritemodrmdw(2,res32,MODRM_src0)) return 1;
		}
	}
	CPUPROT2
	return 0;
}
//For AND
OPTINLINE byte CPU80386_internal_AND32(uint_32 *dest, uint_32 src, byte flags)
{
	if (modrm_check32(&params,MODRM_src0,1)) return 1; //Abort on fault!
	if (!dest) if (modrm_check32(&params,MODRM_src0,0)) return 1; //Abort on fault on write only!
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepreadmodrmdw(0,&oper1d,MODRM_src0)) return 1;
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //Execution step?
	{
		oper1d = dest?*dest:oper1d;
		oper2d = src;
		op_and32();
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
		timing_AND_OR_XOR_ADD_SUB32(dest, flags);
		if (dest==NULL) { CPU[activeCPU].executed = 0; return 1; } //Wait for execution phase to finish!
	}
	if (dest) //Register?
	{
		*dest = res32;
	}
	else //Memory?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepwritemodrmdw(2,res32,MODRM_src0)) return 1;
		}
	}
	CPUPROT2
	return 0;
}


//For SUB
OPTINLINE byte CPU80386_internal_SUB32(uint_32 *dest, uint_32 addition, byte flags)
{
	if (MMU_invaddr())
	{
		return 1;
	}
	if (modrm_check32(&params,MODRM_src0,1)) return 1; //Abort on fault!
	if (!dest) if (modrm_check32(&params,MODRM_src0,0)) return 1; //Abort on fault on write only!
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepreadmodrmdw(0,&oper1d,MODRM_src0)) return 1;
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //Execution step?
	{
		oper1d = dest?*dest:oper1d;
		oper2d = addition;
		op_sub32();
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
		timing_AND_OR_XOR_ADD_SUB32(dest, flags);
		if (dest==NULL) { CPU[activeCPU].executed = 0; return 1; } //Wait for execution phase to finish!
	}
	if (dest) //Register?
	{
		*dest = res32;
	}
	else //Memory?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepwritemodrmdw(2,res32,MODRM_src0)) return 1;
		}
	}
	CPUPROT2
	return 0;
}

//For SBB
OPTINLINE byte CPU80386_internal_SBB32(uint_32 *dest, uint_32 addition, byte flags)
{
	if (MMU_invaddr())
	{
		return 1;
	}
	if (!dest) if (modrm_check32(&params,MODRM_src0,1)) return 1; //Abort on fault!
	if (!dest) if (modrm_check32(&params,MODRM_src0,0)) return 1; //Abort on fault!
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepreadmodrmdw(0,&oper1d,MODRM_src0)) return 1;
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //Execution step?
	{
		oper1d = dest?*dest:oper1d;
		oper2d = addition;
		op_sbb32();
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
		timing_AND_OR_XOR_ADD_SUB32(dest, flags);
		if (dest==NULL) { CPU[activeCPU].executed = 0; return 1; } //Wait for execution phase to finish!
	}
	if (dest) //Register?
	{
		*dest = res32;
	}
	else //Memory?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepwritemodrmdw(2,res32,MODRM_src0)) return 1;
		}
	}
	CPUPROT2
	return 0;
}

//For XOR
//See AND, but XOR
OPTINLINE byte CPU80386_internal_XOR32(uint_32 *dest, uint_32 src, byte flags)
{
	if (MMU_invaddr())
	{
		return 1;
	}
	if (!dest) if (modrm_check32(&params,MODRM_src0,1)) return 1; //Abort on fault!
	if (!dest) if (modrm_check32(&params,MODRM_src0,0)) return 1; //Abort on fault!
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepreadmodrmdw(0,&oper1d,MODRM_src0)) return 1;
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //Execution step?
	{
		oper1d = dest?*dest:oper1d;
		oper2d = src;
		op_xor32();
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
		timing_AND_OR_XOR_ADD_SUB32(dest, flags);
		if (dest==NULL) { CPU[activeCPU].executed = 0; return 1; } //Wait for execution phase to finish!
	}
	if (dest) //Register?
	{
		*dest = res32;
	}
	else //Memory?
	{
		if (dest==NULL) //Needs a read from memory?
		{
			if (CPU80386_internal_stepwritemodrmdw(2,res32,MODRM_src0)) return 1;
		}
	}
	CPUPROT2
	return 0;
}

//TEST : same as AND, but discarding the result!
OPTINLINE byte CPU80386_internal_TEST32(uint_32 dest, uint_32 src, byte flags)
{
	CPUPROT1
	oper1d = dest;
	oper2d = src;
	op_and32();
	//We don't write anything back for TEST, so only execution step is used!
	//Adjust timing for TEST!
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		switch (flags) //What type of operation?
		{
		case 0: //Reg+Reg?
			CPU[activeCPU].cycles_OP += 3; //Reg->Reg!
			break;
		case 1: //Reg+imm?
			CPU[activeCPU].cycles_OP += 4; //Accumulator!
			break;
		case 2: //Determined by ModR/M?
			if (params.EA_cycles) //Memory is used?
			{
				//Mem->Reg/Reg->Mem?
				CPU[activeCPU].cycles_OP += 9-EU_CYCLES_SUBSTRACT_ACCESSREAD; //Mem->Reg!
			}
			else //Reg->Reg?
			{
				CPU[activeCPU].cycles_OP += 3; //Reg->Reg!
			}
			break;
		case 3: //ModR/M+imm?
			if (params.EA_cycles) //Memory is used?
			{
				if (dest) //Imm->Reg?
				{
					CPU[activeCPU].cycles_OP += 5; //Imm->Reg!
				}
				else //Imm->Mem?
				{
					CPU[activeCPU].cycles_OP += 11-EU_CYCLES_SUBSTRACT_ACCESSREAD; //Mem->Reg!
				}
			}
			else //Reg->Reg?
			{
				CPU[activeCPU].cycles_OP += 3; //Reg->Reg!
			}
			break;
		}
	}
	CPUPROT2
	return 0;
}

//Universal DIV instruction for x86 DIV instructions!
/*

Parameters:
	val: The value to divide
	divisor: The value to divide by
	quotient: Quotient result container
	remainder: Remainder result container
	error: 1 on error(DIV0), 0 when valid.
	resultbits: The amount of bits the result contains(16 or 8 on 8086) of quotient and remainder.
	SHLcycle: The amount of cycles for each SHL.
	ADDSUBcycle: The amount of cycles for ADD&SUB instruction to execute.

*/
void CPU80386_internal_DIV(uint_64 val, uint_32 divisor, uint_32 *quotient, uint_32 *remainder, byte *error, byte resultbits, byte SHLcycle, byte ADDSUBcycle, byte *applycycles)
{
	uint_64 temp, temp2, currentquotient; //Remaining value and current divisor!
	byte shift; //The shift to apply! No match on 0 shift is done!
	temp = val; //Load the value to divide!
	*applycycles = 1; //Default: apply the cycles normally!
	if (divisor==0) //Not able to divide?
	{
		*quotient = 0;
		*remainder = temp; //Unable to comply!
		*error = 1; //Divide by 0 error!
		return; //Abort: division by 0!
	}

	if (CPU_apply286cycles()) /* No 80286+ cycles instead? */
	{
		SHLcycle = ADDSUBcycle = 0; //Don't apply the cycle counts for this instruction!
		*applycycles = 0; //Don't apply the cycles anymore!
	}

	temp = val; //Load the remainder to use!
	*quotient = 0; //Default: we have nothing after division! 
	nextstep:
	//First step: calculate shift so that (divisor<<shift)<=remainder and ((divisor<<(shift+1))>remainder)
	temp2 = divisor; //Load the default divisor for x1!
	if (temp2>temp) //Not enough to divide? We're done!
	{
		goto gotresult; //We've gotten a result!
	}
	currentquotient = 1; //We're starting with x1 factor!
	for (shift=0;shift<(resultbits+1);++shift) //Check for the biggest factor to apply(we're going from bit 0 to maxbit)!
	{
		if ((temp2<=temp) && ((temp2<<1)>temp)) //Found our value to divide?
		{
			CPU[activeCPU].cycles_OP += SHLcycle; //We're taking 1 more SHL cycle for this!
			break; //We've found our shift!
		}
		temp2 <<= 1; //Shift to the next position!
		currentquotient <<= 1; //Shift to the next result!
		CPU[activeCPU].cycles_OP += SHLcycle; //We're taking 1 SHL cycle for this! Assuming parallel shifting!
	}
	if (shift==(resultbits+1)) //We've overflown? We're too large to divide!
	{
		*error = 1; //Raise divide by 0 error due to overflow!
		return; //Abort!
	}
	//Second step: substract divisor<<n from remainder and increase result with 1<<n.
	temp -= temp2; //Substract divisor<<n from remainder!
	*quotient += currentquotient; //Increase result(divided value) with the found power of 2 (1<<n).
	CPU[activeCPU].cycles_OP += ADDSUBcycle; //We're taking 1 substract and 1 addition cycle for this(ADD/SUB register take 3 cycles)!
	goto nextstep; //Start the next step!
	//Finished when remainder<divisor or remainder==0.
	gotresult: //We've gotten a result!
	if (temp>((1<<resultbits)-1)) //Modulo overflow?
	{
		*error = 1; //Raise divide by 0 error due to overflow!
		return; //Abort!		
	}
	if (*quotient>((1<<resultbits)-1)) //Quotient overflow?
	{
		*error = 1; //Raise divide by 0 error due to overflow!
		return; //Abort!		
	}
	*remainder = temp; //Give the modulo! The result is already calculated!
	*error = 0; //We're having a valid result!
}

void CPU80386_internal_IDIV(uint_64 val, uint_32 divisor, uint_32 *quotient, uint_32 *remainder, byte *error, byte resultbits, byte SHLcycle, byte ADDSUBcycle, byte *applycycles)
{
	byte quotientnegative, remaindernegative; //To toggle the result and apply sign after and before?
	quotientnegative = remaindernegative = 0; //Default: don't toggle the result not remainder!
	if (((val>>31)!=(divisor>>15))) //Are we to change signs on the result? The result is negative instead! (We're a +/- or -/+ division)
	{
		quotientnegative = 1; //We're to toggle the result sign if not zero!
	}
	if (val&0x80000000) //Negative value to divide?
	{
		val = ((~val)+1); //Convert the negative value to be positive!
		remaindernegative = 1; //We're to toggle the remainder is any, because the value to divide is negative!
	}
	if (divisor&0x8000) //Negative divisor? Convert to a positive divisor!
	{
		divisor = ((~divisor)+1); //Convert the divisor to be positive!
	}
	CPU80386_internal_DIV(val,divisor,quotient,remainder,error,resultbits-1,SHLcycle,ADDSUBcycle,applycycles); //Execute the division as an unsigned division!
	if (*error==0) //No error has occurred? Do post-processing of the results!
	{
		if (quotientnegative) //The result is negative?
		{
			*quotient = (~*quotient)+1; //Apply the new sign to the result!
		}
		if (remaindernegative) //The remainder is negative?
		{
			*remainder = (~*remainder)+1; //Apply the new sign to the remainder!
		}
	}
}

//MOV
OPTINLINE byte CPU80386_internal_MOV8(byte *dest, byte val, byte flags)
{
	if (MMU_invaddr())
	{
		return 1;
	}
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==0) //First step? Execution only!
	{
		if (dest) //Register?
		{
			*dest = val;
			if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
			{
				switch (flags) //What type are we?
				{
				case 0: //Reg+Reg?
					break; //Unused!
				case 1: //Accumulator from immediate memory address?
					CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //[imm16]->Accumulator!
					break;
				case 2: //ModR/M Memory->Reg?
					if (MODRM_EA(params)) //Memory?
					{
						CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Mem->Reg!
					}
					else //Reg->Reg?
					{
						CPU[activeCPU].cycles_OP += 2; //Reg->Reg!
					}
					break;
				case 3: //ModR/M Memory immediate->Reg?
					if (MODRM_EA(params)) //Memory?
					{
						CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Mem->Reg!
					}
					else //Reg->Reg?
					{
						CPU[activeCPU].cycles_OP += 2; //Reg->Reg!
					}
					break;
				case 4: //Register immediate->Reg?
					CPU[activeCPU].cycles_OP += 4; //Reg->Reg!
					break;
				case 8: //SegReg->Reg?
					if ((!MODRM_src1) || (MODRM_EA(params)==0)) //From register?
					{
						CPU[activeCPU].cycles_OP += 2; //Reg->SegReg!
					}
					else //From memory?
					{
						CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Mem->SegReg!
					}
					break;
				}
			}
			++CPU[activeCPU].internalinstructionstep; //Skip the writeback step!
		}
		else //Memory destination?
		{
			if (custommem)
			{
				if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),customoffset,0,getCPL(),!CPU_Address_size[activeCPU],0)) //Error accessing memory?
				{
					return 1; //Abort on fault!
				}
				if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
				{
					CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Accumulator->[imm16]!
				}
			}
			else //ModR/M?
			{
				if (modrm_check8(&params,MODRM_src0,0)) return 1; //Abort on fault!
				if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
				{
					switch (flags) //What type are we?
					{
					case 0: //Reg+Reg?
						break; //Unused!
					case 1: //Accumulator from immediate memory address?
						CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSREAD; //Accumulator->[imm16]!
						break;
					case 2: //ModR/M Memory->Reg?
						if (MODRM_EA(params)) //Memory?
						{
							CPU[activeCPU].cycles_OP += 9-EU_CYCLES_SUBSTRACT_ACCESSREAD; //Mem->Reg!
						}
						else //Reg->Reg?
						{
							CPU[activeCPU].cycles_OP += 2; //Reg->Reg!
						}
						break;
					case 3: //ModR/M Memory immediate->Reg?
						if (MODRM_EA(params)) //Memory?
						{
							CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSREAD; //Mem->Reg!
						}
						else //Reg->Reg?
						{
							CPU[activeCPU].cycles_OP += 4; //Reg->Reg!
						}
						break;
					case 4: //Register immediate->Reg (Non-existant!!!)?
						CPU[activeCPU].cycles_OP += 4; //Reg->Reg!
						break;
					case 8: //Reg->SegReg?
						if (MODRM_src0 || (MODRM_EA(params) == 0)) //From register?
						{
							CPU[activeCPU].cycles_OP += 2; //SegReg->Reg!
						}
						else //From memory?
						{
							CPU[activeCPU].cycles_OP += 9-EU_CYCLES_SUBSTRACT_ACCESSREAD; //SegReg->Mem!
						}
						break;
					}
				}
			}
			++CPU[activeCPU].internalinstructionstep; //Next internal instruction step: memory access!
			CPU[activeCPU].executed = 0; return 1; //Wait for execution phase to finish!
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step: memory access!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //Execution step?
	{
		if (custommem)
		{
			if (CPU8086_internal_stepwritedirectb(0,CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),customoffset,val,!CPU_Address_size[activeCPU])) return 1; //Write to memory directly!
		}
		else //ModR/M?
		{
			if (CPU8086_internal_stepwritemodrmb(0,val,MODRM_src0)) return 1; //Write the result to memory!
		}
		++CPU[activeCPU].internalinstructionstep; //Next step!
	}
	CPUPROT2
	return 0;
}

OPTINLINE byte CPU80386_internal_MOV16(word *dest, word val, byte flags)
{
	if (MMU_invaddr())
	{
		return 1;
	}
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==0) //First step? Execution only!
	{
		if (dest) //Register?
		{
			destEIP = REG_EIP; //Store (E)IP for safety!
			modrm_updatedsegment(dest,val,0); //Check for an updated segment!
			CPUPROT1
			*dest = val;
			if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
			{
				switch (flags) //What type are we?
				{
				case 0: //Reg+Reg?
					break; //Unused!
				case 1: //Accumulator from immediate memory address?
					CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSREAD; //[imm16]->Accumulator!
					break;
				case 2: //ModR/M Memory->Reg?
					if (MODRM_EA(params)) //Memory?
					{
						CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Mem->Reg!
					}
					else //Reg->Reg?
					{
						CPU[activeCPU].cycles_OP += 2; //Reg->Reg!
					}
					break;
				case 3: //ModR/M Memory immediate->Reg?
					if (MODRM_EA(params)) //Memory?
					{
						CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSREAD; //Mem->Reg!
					}
					else //Reg->Reg?
					{
						CPU[activeCPU].cycles_OP += 2; //Reg->Reg!
					}
					break;
				case 4: //Register immediate->Reg?
					CPU[activeCPU].cycles_OP += 4; //Reg->Reg!
					break;
				case 8: //SegReg->Reg?
					if (MODRM_src0 || (MODRM_EA(params) == 0)) //From register?
					{
						CPU[activeCPU].cycles_OP += 2; //Reg->SegReg!
					}
					else //From memory?
					{
						CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; //Mem->SegReg!
					}
					break;
				}
			}
			CPUPROT2
			++CPU[activeCPU].internalinstructionstep; //Skip the memory step!
		}
		else //Memory?
		{
			if (custommem)
			{
				if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),customoffset,0,getCPL(),!CPU_Address_size[activeCPU],0|0x8)) //Error accessing memory?
				{
					return 1; //Abort on fault!
				}
				if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),customoffset+1,0,getCPL(),!CPU_Address_size[activeCPU],1|0x8)) //Error accessing memory?
				{
					return 1; //Abort on fault!
				}
				if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
				{
					CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Accumulator->[imm16]!
				}
			}
			else //ModR/M?
			{
				if (modrm_check16(&params,MODRM_src0,0)) return 1; //Abort on fault!
				if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
				{
					switch (flags) //What type are we?
					{
					case 0: //Reg+Reg?
						break; //Unused!
					case 1: //Accumulator from immediate memory address?
						CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Accumulator->[imm16]!
						break;
					case 2: //ModR/M Memory->Reg?
						if (MODRM_EA(params)) //Memory?
						{
							CPU[activeCPU].cycles_OP += 9-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Mem->Reg!
						}
						else //Reg->Reg?
						{
							CPU[activeCPU].cycles_OP += 2; //Reg->Reg!
						}
						break;
					case 3: //ModR/M Memory immediate->Reg?
						if (MODRM_EA(params)) //Memory?
						{
							CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Mem->Reg!
						}
						else //Reg->Reg?
						{
							CPU[activeCPU].cycles_OP += 4; //Reg->Reg!
						}
						break;
					case 4: //Register immediate->Reg (Non-existant!!!)?
						CPU[activeCPU].cycles_OP += 4; //Reg->Reg!
						break;
					case 8: //Reg->SegReg?
						if (MODRM_src0 || (MODRM_EA(params) == 0)) //From register?
						{
							CPU[activeCPU].cycles_OP += 2; //SegReg->Reg!
						}
						else //From memory?
						{
							CPU[activeCPU].cycles_OP += 9-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //SegReg->Mem!
						}
						break;
					}
				}
			}
			++CPU[activeCPU].internalinstructionstep; //Next internal instruction step: memory access!
			CPU[activeCPU].executed = 0; return 1; //Wait for execution phase to finish!
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step: memory access!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //Execution step?
	{
		if (custommem)
		{
			if (CPU8086_internal_stepwritedirectw(0,CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),customoffset,val,!CPU_Address_size[activeCPU])) return 1; //Write to memory directly!
		}
		else //ModR/M?
		{
			if (CPU8086_internal_stepwritemodrmw(0,val,MODRM_src0,0)) return 1; //Write the result to memory!
		}
		++CPU[activeCPU].internalinstructionstep; //Next step!
	}
	CPUPROT2
	return 0;
}

/*

32-bit move for 80386+

*/

OPTINLINE byte CPU80386_internal_MOV32(uint_32 *dest, uint_32 val, byte flags)
{
	if (MMU_invaddr())
	{
		return 1;
	}
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==0) //First step? Execution only!
	{
		if (dest) //Register?
		{
			//destEIP = REG_EIP; //Store (E)IP for safety!
			//modrm_updatedsegment(dest,val,0); //Check for an updated segment!
			CPUPROT1
			*dest = val;
			if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
			{
				switch (flags) //What type are we?
				{
				case 0: //Reg+Reg?
					break; //Unused!
				case 1: //Accumulator from immediate memory address?
					CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSREAD; //[imm16]->Accumulator!
					break;
				case 2: //ModR/M Memory->Reg?
					if (MODRM_EA(params)) //Memory?
					{
						CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Mem->Reg!
					}
					else //Reg->Reg?
					{
						CPU[activeCPU].cycles_OP += 2; //Reg->Reg!
					}
					break;
				case 3: //ModR/M Memory immediate->Reg?
					if (MODRM_EA(params)) //Memory?
					{
						CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSREAD; //Mem->Reg!
					}
					else //Reg->Reg?
					{
						CPU[activeCPU].cycles_OP += 2; //Reg->Reg!
					}
					break;
				case 4: //Register immediate->Reg?
					CPU[activeCPU].cycles_OP += 4; //Reg->Reg!
					break;
				case 8: //SegReg->Reg?
					if (MODRM_src0 || (MODRM_EA(params) == 0)) //From register?
					{
						CPU[activeCPU].cycles_OP += 2; //Reg->SegReg!
					}
					else //From memory?
					{
						CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; //Mem->SegReg!
					}
					break;
				}
			}
			CPUPROT2
			++CPU[activeCPU].internalinstructionstep; //Skip the memory step!
		}
		else //Memory?
		{
			if (custommem)
			{
				if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),customoffset,0,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) //Error accessing memory?
				{
					return 1; //Abort on fault!
				}
				if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),customoffset+1,0,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) //Error accessing memory?
				{
					return 1; //Abort on fault!
				}
				if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),customoffset+2,0,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) //Error accessing memory?
				{
					return 1; //Abort on fault!
				}
				if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),customoffset+3,0,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) //Error accessing memory?
				{
					return 1; //Abort on fault!
				}
				if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
				{
					CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Accumulator->[imm16]!
				}
			}
			else //ModR/M?
			{
				if (modrm_check32(&params,MODRM_src0,0)) return 1; //Abort on fault!
				if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
				{
					switch (flags) //What type are we?
					{
					case 0: //Reg+Reg?
						break; //Unused!
					case 1: //Accumulator from immediate memory address?
						CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Accumulator->[imm16]!
						break;
					case 2: //ModR/M Memory->Reg?
						if (MODRM_EA(params)) //Memory?
						{
							CPU[activeCPU].cycles_OP += 9-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Mem->Reg!
						}
						else //Reg->Reg?
						{
							CPU[activeCPU].cycles_OP += 2; //Reg->Reg!
						}
						break;
					case 3: //ModR/M Memory immediate->Reg?
						if (MODRM_EA(params)) //Memory?
						{
							CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Mem->Reg!
						}
						else //Reg->Reg?
						{
							CPU[activeCPU].cycles_OP += 4; //Reg->Reg!
						}
						break;
					case 4: //Register immediate->Reg (Non-existant!!!)?
						CPU[activeCPU].cycles_OP += 4; //Reg->Reg!
						break;
					case 8: //Reg->SegReg?
						if (MODRM_src0 || (MODRM_EA(params) == 0)) //From register?
						{
							CPU[activeCPU].cycles_OP += 2; //SegReg->Reg!
						}
						else //From memory?
						{
							CPU[activeCPU].cycles_OP += 9-EU_CYCLES_SUBSTRACT_ACCESSWRITE; //SegReg->Mem!
						}
						break;
					}
				}
			}
			++CPU[activeCPU].internalinstructionstep; //Next internal instruction step: memory access!
			CPU[activeCPU].executed = 0; return 1; //Wait for execution phase to finish!
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step: memory access!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //Execution step?
	{
		if (custommem)
		{
			if (CPU80386_internal_stepwritedirectdw(0,CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),customoffset,val,!CPU_Address_size[activeCPU])) return 1; //Write to memory directly!
		}
		else //ModR/M?
		{
			if (CPU80386_internal_stepwritemodrmdw(0,val,MODRM_src0)) return 1; //Write the result to memory!
		}
		++CPU[activeCPU].internalinstructionstep; //Next step!
	}
	CPUPROT2
	return 0;
}


/*

80386 special

*/
//LEA for LDS, LES
OPTINLINE uint_32 getLEA32(MODRM_PARAMS *theparams)
{
	return modrm_lea32(theparams,1);
}


/*

Non-logarithmic opcodes for 80386+!

*/

//BCD opcodes!
OPTINLINE void CPU80386_internal_DAA()
{
	word ALVAL, oldCF;
	CPUPROT1
	oldCF = FLAG_CF; //Save old Carry!
	ALVAL = (word)REG_AL;
	if (((ALVAL&0xF)>9) || FLAG_AF)
	{
		oper1 = ALVAL+6;
		ALVAL = (oper1&0xFF);
		FLAGW_AF(1);
	}
	else FLAGW_AF(0);
	if (((REG_AL)>0x99) || oldCF)
	{
		ALVAL += 0x60;
		FLAGW_CF(1);
	}
	else
	{
		FLAGW_CF(0);
	}
	REG_AL = (byte)(ALVAL&0xFF); //Write the value back to AL!
	flag_szp8(REG_AL);
	//if (ALVAL&0xFF00) FLAGW_OF(1); else FLAGW_OF(0); //Undocumented: Overflow flag!
	CPUPROT2
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		CPU[activeCPU].cycles_OP += 4; //Timings!
	}
}
OPTINLINE void CPU80386_internal_DAS()
{
	INLINEREGISTER byte tempCF, tempAL;
	INLINEREGISTER word bigAL;
	bigAL = (word)(tempAL = REG_AL);
	tempCF = FLAG_CF; //Save old values!
	CPUPROT1
	if (((bigAL&0xF)>9) || FLAG_AF)
	{
		oper1 = bigAL = REG_AL-6;
		REG_AL = oper1&255;
		FLAGW_CF(tempCF|((oper1&0xFF00)>0));
		FLAGW_AF(1);
	}
	else FLAGW_AF(0);

	if ((tempAL>0x99) || tempCF)
	{
		bigAL -= 0x60;
		REG_AL = (byte)(bigAL&0xFF);
		FLAGW_CF(1);
	}
	else
	{
		FLAGW_CF(0);
	}
	flag_szp8(REG_AL);
	//if (bigAL&0xFF00) FLAGW_OF(1); else FLAGW_OF(0); //Undocumented: Overflow flag!
	CPUPROT2
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		CPU[activeCPU].cycles_OP += 4; //Timings!
	}
}
OPTINLINE void CPU80386_internal_AAA()
{
	CPUPROT1
	if (((REG_AL&0xF)>9) || FLAG_AF)
	{
		REG_AX += 0x0106;
		FLAGW_AF(1);
		FLAGW_CF(1);
	}
	else
	{
		FLAGW_AF(0);
		FLAGW_CF(0);
	}
	REG_AL &= 0xF;
	//flag_szp8(REG_AL); //Basic flags!
	flag_p8(REG_AL); //Parity is affected!
	FLAGW_ZF((REG_AL==0)?1:0); //Zero is affected!
	FLAGW_SF(0); //Clear Sign!
	//z=s=p=o=?
	CPUPROT2
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		CPU[activeCPU].cycles_OP += 4; //Timings!
	}
}
OPTINLINE void CPU80386_internal_AAS()
{
	CPUPROT1
	if (((REG_AL&0xF)>9) || FLAG_AF)
	{
		REG_AX -= 0x0106;
		FLAGW_AF(1);
		FLAGW_CF(1);
	}
	else
	{
		FLAGW_AF(0);
		FLAGW_CF(0);
	}
	REG_AL &= 0xF;
	//flag_szp8(REG_AL); //Basic flags!
	flag_p8(REG_AL); //Parity is affected!
	FLAGW_ZF((REG_AL==0)?1:0); //Zero is affected!
	FLAGW_SF(0); //Sign is cleared!
	//z=s=o=p=?
	CPUPROT2
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		CPU[activeCPU].cycles_OP += 4; //Timings!
	}
}

OPTINLINE byte CPU80386_internal_AAM(byte data)
{
	CPUPROT1
	if ((!data) && (CPU[activeCPU].instructionstep==0)) //First step?
	{
		CPU[activeCPU].cycles_OP += 1; //Timings always!
		++CPU[activeCPU].instructionstep; //Next step after we're done!
		CPU[activeCPU].executed = 0; //Not executed yet!
		return 1;
	}
	word quotient, remainder;
	byte error, applycycles;
	CPU8086_internal_DIV(REG_AL,data,&quotient,&remainder,&error,8,2,6,&applycycles);
	if (error) //Error occurred?
	{
		CPU_exDIV0(); //Raise error that's requested!
		return 1;
	}
	else //Valid result?
	{
		REG_AH = (byte)(quotient&0xFF);
		REG_AL = (byte)(remainder&0xFF);
		//Flags are set on newer CPUs according to the MOD operation: Sign, Zero and Parity are set according to the mod operation(AL) and Overflow, Carry and Auxiliary carry are cleared.
		flag_szp8(REG_AL); //Result of MOD instead!
		FLAGW_OF(0); FLAGW_CF(0); FLAGW_AF(0); //Clear these!
		//C=O=A=?
	}
	CPUPROT2
	CPU[activeCPU].cycles_OP = 83; //Timings!
	return 0;
}

OPTINLINE void op_add8_386() {
	res8 = oper1b + oper2b;
	flag_add8 (oper1b, oper2b);
}

OPTINLINE byte CPU80386_internal_AAD(byte data)
{
	CPUPROT1
	oper2b = REG_AL; //What to add!
	REG_AL = (REG_AH*data);    //AAD
	oper1b = REG_AL; //Load for addition!
	op_add8_386(); //Add, 8-bit, including flags!
	REG_AL = res8; //The result to load!
	REG_AH = 0; //AH is cleared!
	//C=O=A=?
	CPUPROT2
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		CPU[activeCPU].cycles_OP += 60; //Timings!
	}
	CPU[activeCPU].cycles_OP = 60; //Timings!
	return 0;
}

OPTINLINE void CPU80386_internal_CWDE()
{
	CPUPROT1
	if ((REG_AX&0x8000)==0x8000)
	{
		REG_EAX |= 0xFFFF0000;
	}
	else
	{
		REG_EAX &= 0xFFFF;
	}
	CPU[activeCPU].cycles_OP = 2; //Clock cycles!
	CPUPROT2
}
OPTINLINE void CPU80386_internal_CDQ()
{
	CPUPROT1
	if ((REG_EAX&0x80000000)==0x80000000)
	{
		REG_EDX = 0xFFFFFFFF;
	}
	else
	{
		REG_EDX = 0;
	}
	CPU[activeCPU].cycles_OP = 5; //Clock cycles!
	CPUPROT2
}

//Now the repeatable instructions!

/*

80386 versions of the 8086+ 16-bit instructions!

*/

extern byte newREP; //Are we a new repeating instruction (REP issued for a new instruction, not repeating?)

uint_32 MOVSD_data;
OPTINLINE byte CPU80386_internal_MOVSD()
{
	if (blockREP) return 1; //Disabled REP!
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size[activeCPU]?REG_ESI:REG_SI),1,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size[activeCPU]?REG_ESI:REG_SI)+1,1,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size[activeCPU]?REG_ESI:REG_SI)+2,1,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size[activeCPU]?REG_ESI:REG_SI)+3,1,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_SEGMENT_ES,REG_ES,(CPU_Address_size[activeCPU]?REG_EDI:REG_DI),0,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_SEGMENT_ES,REG_ES,(CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+1,0,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_SEGMENT_ES,REG_ES,(CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+2,0,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_SEGMENT_ES,REG_ES,(CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+3,0,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		++CPU[activeCPU].internalinstructionstep; //Next step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //First Execution step?
	{
		//Needs a read from memory?
		if (CPU80386_internal_stepreaddirectdw(0,CPU_segment_index(CPU_SEGMENT_DS), CPU_segment(CPU_SEGMENT_DS), (CPU_Address_size[activeCPU]?REG_ESI:REG_SI), &MOVSD_data,!CPU_Address_size[activeCPU])) return 1; //Try to read the data!
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	if (CPU[activeCPU].internalinstructionstep==2) //Execution step?
	{
		if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
		{
			if (CPU[activeCPU].repeating) //Are we a repeating instruction?
			{
				if (newREP) //Include the REP?
				{
					CPU[activeCPU].cycles_OP += 9 + 17 - (EU_CYCLES_SUBSTRACT_ACCESSRW); //Clock cycles including REP!
				}
				else //Repeating instruction itself?
				{
					CPU[activeCPU].cycles_OP += 17 - (EU_CYCLES_SUBSTRACT_ACCESSRW); //Clock cycles excluding REP!
				}
			}
			else //Plain non-repeating instruction?
			{
				CPU[activeCPU].cycles_OP += 18 - (EU_CYCLES_SUBSTRACT_ACCESSRW); //Clock cycles!
			}
		}
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
		CPU[activeCPU].executed = 0; return 1; //Wait for execution phase to finish!
	}
	//Writeback phase!
	if (CPU80386_internal_stepwritedirectdw(2,CPU_SEGMENT_ES,REG_ES,(CPU_Address_size[activeCPU]?REG_EDI:REG_DI),MOVSD_data,!CPU_Address_size[activeCPU])) return 1;
	CPUPROT1
	if (FLAG_DF)
	{
		if (CPU_Address_size[activeCPU])
		{
			REG_ESI -= 4;
			REG_EDI -= 4;
		}
		else
		{
			REG_SI -= 4;
			REG_DI -= 4;
		}
	}
	else
	{
		if (CPU_Address_size[activeCPU])
		{
			REG_ESI += 4;
			REG_EDI += 4;
		}
		else
		{
			REG_SI += 4;
			REG_DI += 4;
		}
	}
	CPUPROT2
	return 0;
}

uint_32 CMPSD_data1,CMPSD_data2;
OPTINLINE byte CPU80386_internal_CMPSD()
{
	if (blockREP) return 1; //Disabled REP!
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS), CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size[activeCPU]?REG_ESI:REG_SI),1,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS), CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size[activeCPU]?REG_ESI:REG_SI)+1,1,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS), CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size[activeCPU]?REG_ESI:REG_SI)+2,1,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS), CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size[activeCPU]?REG_ESI:REG_SI)+3,1,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_SEGMENT_ES, REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI),1,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_SEGMENT_ES, REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+1,1,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_SEGMENT_ES, REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+2,1,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_SEGMENT_ES, REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+3,1,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		++CPU[activeCPU].internalinstructionstep; //Next step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //First Execution step?
	{
		//Needs a read from memory?
		if (CPU80386_internal_stepreaddirectdw(0,CPU_segment_index(CPU_SEGMENT_DS), CPU_segment(CPU_SEGMENT_DS), (CPU_Address_size[activeCPU]?REG_ESI:REG_SI),&CMPSD_data1,!CPU_Address_size[activeCPU])) return 1; //Try to read the data!
		if (CPU80386_internal_stepreaddirectdw(2,CPU_SEGMENT_ES, REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI), &CMPSD_data2,!CPU_Address_size[activeCPU])) return 1; //Try to read the data!
		
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	CMP_dw(CMPSD_data1,CMPSD_data2,4);
	if (FLAG_DF)
	{
		if (CPU_Address_size[activeCPU])
		{
			REG_ESI -= 4;
			REG_EDI -= 4;
		}
		else
		{
			REG_SI -= 4;
			REG_DI -= 4;
		}
	}
	else
	{
		if (CPU_Address_size[activeCPU])
		{
			REG_ESI += 4;
			REG_EDI += 4;
		}
		else
		{
			REG_SI += 4;
			REG_DI += 4;
		}
	}

	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		if (CPU[activeCPU].repeating) //Are we a repeating instruction?
		{
			if (newREP) //Include the REP?
			{
				CPU[activeCPU].cycles_OP += 9 + 22 - (EU_CYCLES_SUBSTRACT_ACCESSREAD*2); //Clock cycles including REP!
			}
			else //Repeating instruction itself?
			{
				CPU[activeCPU].cycles_OP += 22 - (EU_CYCLES_SUBSTRACT_ACCESSREAD*2); //Clock cycles excluding REP!
			}
		}
		else //Plain non-repeating instruction?
		{
			CPU[activeCPU].cycles_OP += 22 - (EU_CYCLES_SUBSTRACT_ACCESSREAD*2); //Clock cycles!
		}
	}
	return 0;
}

OPTINLINE byte CPU80386_internal_STOSD()
{
	if (blockREP) return 1; //Disabled REP!
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (checkMMUaccess(CPU_SEGMENT_ES, REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI),0,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_SEGMENT_ES, REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+1,0,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_SEGMENT_ES, REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+2,0,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_SEGMENT_ES, REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+3,0,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		++CPU[activeCPU].internalinstructionstep; //Next step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //First Execution step?
	{
		//Needs a read from memory?
		if (CPU80386_internal_stepwritedirectdw(0,CPU_segment_index(CPU_SEGMENT_ES),REG_ES,(CPU_Address_size[activeCPU]?REG_EDI:REG_DI),REG_EAX,!CPU_Address_size[activeCPU])) return 1; //Try to read the data!
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	CPUPROT1
	if (FLAG_DF)
	{
		if (CPU_Address_size[activeCPU])
		{
			REG_EDI -= 4;
		}
		else
		{
			REG_DI -= 4;
		}
	}
	else
	{
		if (CPU_Address_size[activeCPU])
		{
			REG_EDI += 4;
		}
		else
		{
			REG_DI += 4;
		}
	}
	CPUPROT2
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		if (CPU[activeCPU].repeating) //Are we a repeating instruction?
		{
			if (newREP) //Include the REP?
			{
				CPU[activeCPU].cycles_OP += 9 + 10 - EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Clock cycles including REP!
			}
			else //Repeating instruction itself?
			{
				CPU[activeCPU].cycles_OP += 10 - EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Clock cycles excluding REP!
			}
		}
		else //Plain non-repeating instruction?
		{
			CPU[activeCPU].cycles_OP += 11 - EU_CYCLES_SUBSTRACT_ACCESSWRITE; //Clock cycles!
		}
	}
	++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	return 0;
}
//OK so far!

uint_32 LODSD_value;
OPTINLINE byte CPU80386_internal_LODSD()
{
	if (blockREP) return 1; //Disabled REP!
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS), CPU_segment(CPU_SEGMENT_DS), (CPU_Address_size[activeCPU]?REG_ESI:REG_SI),1,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS), CPU_segment(CPU_SEGMENT_DS), (CPU_Address_size[activeCPU]?REG_ESI:REG_SI)+1,1,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS), CPU_segment(CPU_SEGMENT_DS), (CPU_Address_size[activeCPU]?REG_ESI:REG_SI)+2,1,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS), CPU_segment(CPU_SEGMENT_DS), (CPU_Address_size[activeCPU]?REG_ESI:REG_SI)+3,1,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		++CPU[activeCPU].internalinstructionstep;
	}
	if (CPU[activeCPU].internalinstructionstep==1) //First Execution step?
	{
		//Needs a read from memory?
		if (CPU80386_internal_stepreaddirectdw(0,CPU_segment_index(CPU_SEGMENT_DS), CPU_segment(CPU_SEGMENT_DS), (CPU_Address_size[activeCPU]?REG_ESI:REG_SI), &LODSD_value,!CPU_Address_size[activeCPU])) return 1; //Try to read the data!
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	CPUPROT1
	REG_EAX = LODSD_value;
	if (FLAG_DF)
	{
		if (CPU_Address_size[activeCPU])
		{
			REG_ESI -= 4;
		}
		else
		{
			REG_SI -= 4;
		}
	}
	else
	{
		if (CPU_Address_size[activeCPU])
		{
			REG_ESI += 4;
		}
		else
		{
			REG_SI += 4;
		}
	}
	CPUPROT2
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		if (CPU[activeCPU].repeating) //Are we a repeating instruction?
		{
			if (newREP) //Include the REP?
			{
				CPU[activeCPU].cycles_OP += 9 + 13 - EU_CYCLES_SUBSTRACT_ACCESSREAD; //Clock cycles including REP!
			}
			else //Repeating instruction itself?
			{
				CPU[activeCPU].cycles_OP += 13 - EU_CYCLES_SUBSTRACT_ACCESSREAD; //Clock cycles excluding REP!
			}
		}
		else //Plain non-repeating instruction?
		{
			CPU[activeCPU].cycles_OP += 12 - EU_CYCLES_SUBSTRACT_ACCESSREAD; //Clock cycles!
		}
	}
	return 0;
}

uint_32 SCASD_cmp1;
OPTINLINE byte CPU80386_internal_SCASD()
{
	if (blockREP) return 1; //Disabled REP!
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_ES), REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI),1,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_ES), REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+1,1,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_ES), REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+2,1,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_ES), REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+3,1,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) //Error accessing memory?
		{
			return 1; //Abort on fault!
		}
		++CPU[activeCPU].internalinstructionstep;
	}
	if (CPU[activeCPU].internalinstructionstep==1) //First Execution step?
	{
		//Needs a read from memory?
		if (CPU80386_internal_stepreaddirectdw(0,CPU_segment_index(CPU_SEGMENT_ES), REG_ES, (CPU_Address_size[activeCPU]?REG_EDI:REG_DI), &SCASD_cmp1,!CPU_Address_size[activeCPU])) return 1; //Try to read the data!
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}

	CPUPROT1
	CMP_dw(REG_EAX,SCASD_cmp1,4);
	if (FLAG_DF)
	{
		if (CPU_Address_size[activeCPU])
		{
			REG_EDI -= 4;
		}
		else
		{
			REG_DI -= 4;
		}
	}
	else
	{
		if (CPU_Address_size[activeCPU])
		{
			REG_EDI += 4;
		}
		else
		{
			REG_DI += 4;
		}
	}
	CPUPROT2
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		if (CPU[activeCPU].repeating) //Are we a repeating instruction?
		{
			if (newREP) //Include the REP?
			{
				CPU[activeCPU].cycles_OP += 9 + 15 - EU_CYCLES_SUBSTRACT_ACCESSREAD; //Clock cycles including REP!
			}
			else //Repeating instruction itself?
			{
				CPU[activeCPU].cycles_OP += 15 - EU_CYCLES_SUBSTRACT_ACCESSREAD; //Clock cycles excluding REP!
			}
		}
		else //Plain non-repeating instruction?
		{
			CPU[activeCPU].cycles_OP += 15 - EU_CYCLES_SUBSTRACT_ACCESSREAD; //Clock cycles!
		}
	}
	return 0;
}

OPTINLINE byte CPU80386_instructionstepPOPtimeout(byte base)
{
	return CPU8086_instructionstepdelayBIU(base,2);//Delay 2 cycles for POPs to start!
}

OPTINLINE byte CPU80386_internal_POPtimeout(byte base)
{
	return CPU8086_internal_delayBIU(base,2);//Delay 2 cycles for POPs to start!
}

uint_32 RETD_val;
OPTINLINE byte CPU80386_internal_RET(word popbytes, byte isimm)
{
	if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,0,0)) return 1; ++CPU[activeCPU].stackchecked; }
	if (CPU80386_internal_POPtimeout(0)) return 1; //POP timeout!
	if (CPU80386_internal_POPdw(2,&RETD_val)) return 1;
    //Near return
	CPUPROT1
	CPU_JMPabs(RETD_val);
	CPU_flushPIQ(-1); //We're jumping to another address!
	if (STACK_SEGMENT_DESCRIPTOR_B_BIT())
	{
		REG_ESP += popbytes;
	}
	else
	{
		REG_SP += popbytes;
	}
	CPUPROT2
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		if (isimm)
			CPU[activeCPU].cycles_OP += 12 - EU_CYCLES_SUBSTRACT_ACCESSREAD; /* Intrasegment with constant */
		else
			CPU[activeCPU].cycles_OP += 8 - EU_CYCLES_SUBSTRACT_ACCESSREAD; /* Intrasegment */
		CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; //Stall the BIU completely now!
	}
	return 0;
}
extern word RETF_destCS; //Use 8086 location as well!
uint_32 RETFD_val; //Far return

OPTINLINE byte CPU80386_internal_RETF(word popbytes, byte isimm)
{
	if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(2,0,0)) return 1; ++CPU[activeCPU].stackchecked; }
	if (CPU80386_internal_POPtimeout(0)) return 1; //POP timeout!
	if (CPU80386_internal_POPdw(2,&RETFD_val)) return 1;
	CPUPROT1
	if (CPU8086_internal_POPw(4,&RETF_destCS)) return 1;
	CPUPROT1
	destEIP = RETFD_val; //Load IP!
	segmentWritten(CPU_SEGMENT_CS,RETF_destCS,4); //CS changed, we're a RETF instruction!
	CPU_flushPIQ(-1); //We're jumping to another address!
	CPUPROT1
	if (STACK_SEGMENT_DESCRIPTOR_B_BIT())
	{
		REG_ESP += popbytes; //Process ESP!
	}
	else
	{
		REG_SP += popbytes; //Process SP!
	}
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		if (isimm)
			CPU[activeCPU].cycles_OP += 17 - (EU_CYCLES_SUBSTRACT_ACCESSREAD*2); /* Intersegment with constant */
		else
			CPU[activeCPU].cycles_OP += 18 - (EU_CYCLES_SUBSTRACT_ACCESSREAD*2); /* Intersegment */
		CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; //Stall the BIU completely now!
	}
	CPUPROT2
	CPUPROT2
	CPUPROT2
	return 0;
}
void external80386RETF(word popbytes)
{
	CPU80386_internal_RETF(popbytes,1); //Return immediate variant!
}

extern uint_32 exception_busy; //Exception is busy?
extern byte tempcycles;

OPTINLINE byte CPU80386_internal_INTO()
{
	if (exception_busy&0x10) goto busyEX4;
	if (FLAG_OF==0) goto finishINTO; //Finish?
	exception_busy |= 0x10; //We're busy!
	if (CPU_faultraised(EXCEPTION_OVERFLOW)==0) //Fault raised?
	{
		exception_busy &= ~0x10; //Not busy anymore!
		return 1; //Abort handling when needed!
	}
	busyEX4:
	tempcycles = CPU[activeCPU].cycles_OP; //Save old cycles!
	if ((CPU086_int(EXCEPTION_OVERFLOW)==0) && (!(EMULATED_CPU>=CPU_80286))) return 1; //Return to opcode!
	exception_busy &= ~0x10; //Not busy anymore!
	CPU[activeCPU].cycles_Exception += CPU[activeCPU].cycles_OP; //Our cycles are counted as a hardware interrupt's cycles instead!
	CPU[activeCPU].cycles_OP = tempcycles; //Restore cycles!
	return 0; //Finished: OK!
	finishINTO:
	{
		if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
		{
			CPU[activeCPU].cycles_OP += 4; //Timings!
		}
	}
	return 0; //Finished: OK!
}

extern byte XLAT_value; //XLAT

OPTINLINE byte CPU80386_internal_XLAT()
{
	if (cpudebugger) //Debugger on?
	{
		debugger_setcommand("XLAT");    //XLAT
	}
	if (CPU[activeCPU].internalinstructionstep==0) //First step?
	{
		if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size?REG_EBX:REG_BX)+REG_AL,0,getCPL(),!CPU_Address_size[activeCPU],0)) return 1; //Abort on fault!
		++CPU[activeCPU].internalinstructionstep; //Next step!
	}
	if (CPU[activeCPU].internalinstructionstep==1) //First Execution step?
	{
		//Needs a read from memory?
		if (CPU8086_internal_stepreaddirectb(0,CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size?REG_EBX:REG_BX)+REG_AL,&XLAT_value,!CPU_Address_size[activeCPU])) return 1; //Try to read the data!
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	CPUPROT1
	REG_AL = XLAT_value;
	CPUPROT2
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		CPU[activeCPU].cycles_OP += 11 - EU_CYCLES_SUBSTRACT_ACCESSREAD; //XLAT timing!
	}
	return 0;
}

extern byte secondparambase, writebackbase;
OPTINLINE byte CPU80386_internal_XCHG8(byte *data1, byte *data2, byte flags)
{
	if (CPU[activeCPU].internalinstructionstep==0)
	{
		if (!data1) if (modrm_check8(&params,MODRM_src0,1)) return 1; //Abort on fault!
		if (!data1) if (modrm_check8(&params,MODRM_src0,0)) return 1; //Abort on fault!
		secondparambase = (data1||data2)?0:2; //Second param base
		writebackbase = ((data2==NULL) && (data1==NULL))?4:2; //Write back param base
		if (!data2) if (modrm_check8(&params,MODRM_src1,1)) return 1; //Abort on fault!
		if (!data2) if (modrm_check8(&params,MODRM_src1,0)) return 1; //Abort on fault!
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==1) //First step?
	{
		if (data1==NULL) if (CPU8086_internal_stepreadmodrmb(0,&oper1b,MODRM_src0)) return 1;
		if (data2==NULL) if (CPU8086_internal_stepreadmodrmb(secondparambase,&oper2b,MODRM_src1)) return 1;
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	if (CPU[activeCPU].internalinstructionstep==2) //Execution step?
	{
		oper1b = data1?*data1:oper1b;
		oper2b = data2?*data2:oper2b;
		INLINEREGISTER byte temp = oper1b; //Copy!
		oper1b = oper2b; //We're ...
		oper2b = temp; //Swapping this!
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
		if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
		{
			switch (flags)
			{
			case 0: //Unknown?
				break;
			case 1: //Acc<->Reg?
				CPU[activeCPU].cycles_OP += 3; //Acc<->Reg!
				break;
			case 2: //Mem<->Reg?
				if (MODRM_EA(params)) //Reg<->Mem?
				{
					CPU[activeCPU].cycles_OP += 17 - (EU_CYCLES_SUBSTRACT_ACCESSRW*2); //SegReg->Mem!
				}
				else //Reg<->Reg?
				{
					CPU[activeCPU].cycles_OP += 4; //SegReg->Mem!
				}
				break;
			}
		}
		if ((data1==NULL) || (data2==NULL)) { CPU[activeCPU].executed = 0; return 1; } //Wait for execution phase to finish!
	}
	if (data1) //Register?
	{
		*data1 = oper1b;
	}
	else //Memory?
	{
		if (CPU8086_internal_stepwritemodrmb(writebackbase,oper1b,MODRM_src0)) return 1;
	}
	
	if (data2)
	{
		*data2 = oper2b;
	}
	else
	{
		if (CPU8086_internal_stepwritemodrmb(writebackbase+secondparambase,oper2b,MODRM_src1)) return 1;
	}
	CPUPROT2
	return 0;
}

OPTINLINE byte CPU80386_internal_XCHG32(uint_32 *data1, uint_32 *data2, byte flags)
{
	if (CPU[activeCPU].internalinstructionstep==0)
	{
		if (!data1) if (modrm_check32(&params,MODRM_src0,1)) return 1; //Abort on fault!
		if (!data1) if (modrm_check32(&params,MODRM_src0,0)) return 1; //Abort on fault!
		secondparambase = (data1||data2)?0:2; //Second param base
		writebackbase = ((data2==NULL) && (data1==NULL))?4:2; //Write back param base
		if (!data2) if (modrm_check32(&params,MODRM_src1,1)) return 1; //Abort on fault!
		if (!data2) if (modrm_check32(&params,MODRM_src1,0)) return 1; //Abort on fault!
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==1) //First step?
	{
		if (data1==NULL) if (CPU80386_internal_stepreadmodrmdw(0,&oper1d,MODRM_src0)) return 1;
		if (data2==NULL) if (CPU80386_internal_stepreadmodrmdw(secondparambase,&oper2d,MODRM_src1)) return 1;
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	if (CPU[activeCPU].internalinstructionstep==2) //Execution step?
	{
		oper1d = data1?*data1:oper1d;
		oper2d = data2?*data2:oper2d;
		INLINEREGISTER uint_32 temp = oper1d; //Copy!
		oper1d = oper2d; //We're ...
		oper2d = temp; //Swapping this!
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
		if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
		{
			switch (flags)
			{
			case 0: //Unknown?
				break;
			case 1: //Acc<->Reg?
				CPU[activeCPU].cycles_OP += 3; //Acc<->Reg!
				break;
			case 2: //Mem<->Reg?
				if (MODRM_EA(params)) //Reg<->Mem?
				{
					CPU[activeCPU].cycles_OP += 17 - (EU_CYCLES_SUBSTRACT_ACCESSRW*2); //SegReg->Mem!
				}
				else //Reg<->Reg?
				{
					CPU[activeCPU].cycles_OP += 4; //SegReg->Mem!
				}
				break;
			}
		}
		if ((data1==NULL) || (data2==NULL)) { CPU[activeCPU].executed = 0; return 1; } //Wait for execution phase to finish!
	}

	if (data1) //Register?
	{
		*data1 = oper1d;
	}
	else //Memory?
	{
		if (CPU80386_internal_stepwritemodrmdw(writebackbase,oper1d,MODRM_src0)) return 1;
	}
	
	if (data2)
	{
		*data2 = oper2d;
	}
	else
	{
		if (CPU80386_internal_stepwritemodrmdw(writebackbase+secondparambase,oper2d,MODRM_src1)) return 1;
	}
	CPUPROT2
	return 0;
}

extern byte modrm_addoffset; //Add this offset to ModR/M reads!

byte CPU80386_internal_LXS(int segmentregister) //LDS, LES etc.
{
	static word segment;
	static uint_32 offset;

	if (CPU[activeCPU].internalinstructionstep==0)
	{
		modrm_addoffset = 0; //Add this to the offset to use!
		if (modrm_check32(&params,MODRM_src1,1)) return 1; //Abort on fault!
		modrm_addoffset = 4; //Add this to the offset to use!
		if (modrm_check16(&params,MODRM_src1,1)) return 1; //Abort on fault!
		modrm_addoffset = 0;
		if (modrm_check32(&params,MODRM_src0,0)) return 1; //Abort on fault for the used segment itself!
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	CPUPROT1
	if (CPU[activeCPU].internalinstructionstep==1) //First step?
	{
		modrm_addoffset = 0; //Add this to the offset to use!
		if (CPU80386_internal_stepreadmodrmdw(0,&offset,MODRM_src1)) return 1;
		modrm_addoffset = 4; //Add this to the offset to use!
		if (CPU8086_internal_stepreadmodrmw(2,&segment,MODRM_src1)) return 1;
		modrm_addoffset = 0; //Reset again!
		++CPU[activeCPU].internalinstructionstep; //Next internal instruction step!
	}
	//Execution phase!
	CPUPROT1
	destEIP = REG_EIP; //Save EIP for transfers!
	segmentWritten(segmentregister, segment,0); //Load the new segment!
	CPUPROT1
	modrm_write32(&params, MODRM_src0, offset); //Try to load the new register with the offset!
	CPUPROT2
	CPUPROT2
	CPUPROT2
	if (CPU_apply286cycles()==0) //No 80286+ cycles instead?
	{
		if (MODRM_EA(params)) //Memory?
		{
			CPU[activeCPU].cycles_OP += 16 - (EU_CYCLES_SUBSTRACT_ACCESSREAD*2); /* LXS based on MOV Mem->SS, DS, ES */
		}
		else //Register? Should be illegal?
		{
			CPU[activeCPU].cycles_OP += 2; /* LXS based on MOV Mem->SS, DS, ES */
		}
	}
	return 0;
}

byte CPU80386_CALLF(word segment, uint_32 offset)
{
	destEIP = offset;
	segmentWritten(CPU_SEGMENT_CS, segment, 2); /*CS changed, call version!*/
	CPU_flushPIQ(-1); //We're jumping to another address!
	return 0;
}

/*

NOW THE REAL OPCODES!

*/

extern byte didJump; //Did we jump this instruction?

//Temporarily disabled to check for unmodified instructions:
extern byte instructionbufferb, instructionbufferb2; //For 8-bit read storage!
extern word instructionbufferw, instructionbufferw2; //For 16-bit read storage!
uint_32 instructionbufferd=0, instructionbufferd2=0; //For 16-bit read storage!

void CPU80386_OP01() {modrm_generateInstructionTEXT("ADDD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_ADD32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP03() {modrm_generateInstructionTEXT("ADDD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_ADD32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP05() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("ADDD EAX,",0,theimm,PARAM_IMM32); CPU80386_internal_ADD32(&REG_EAX,theimm,1); }
void CPU80386_OP09() {modrm_generateInstructionTEXT("ORD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_OR32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP0B() {modrm_generateInstructionTEXT("ORD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_OR32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP0D() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("ORD EAX,",0,theimm,PARAM_IMM32); CPU80386_internal_OR32(&REG_EAX,theimm,1); }
void CPU80386_OP11() {modrm_generateInstructionTEXT("ADCD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_ADC32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP13() {modrm_generateInstructionTEXT("ADCD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_ADC32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP15() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("ADCD EAX,",0,theimm,PARAM_IMM32); CPU80386_internal_ADC32(&REG_EAX,theimm,1); }
void CPU80386_OP19() {modrm_generateInstructionTEXT("SBBD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_SBB32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP1B() {modrm_generateInstructionTEXT("SBBD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_SBB32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP1D() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("SBBD EAX,",0,theimm,PARAM_IMM32); CPU80386_internal_SBB32(&REG_EAX,theimm,1); }
void CPU80386_OP21() {modrm_generateInstructionTEXT("ANDD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_AND32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP23() {modrm_generateInstructionTEXT("ANDD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_AND32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP25() {INLINEREGISTER uint_32 theimm = immw; modrm_generateInstructionTEXT("ANDD EAX,",0,theimm,PARAM_IMM32); CPU80386_internal_AND32(&REG_EAX,theimm,1); }
void CPU80386_OP27() {modrm_generateInstructionTEXT("DAA",0,0,PARAM_NONE);/*DAA?*/ CPU80386_internal_DAA();/*DAA?*/ }
void CPU80386_OP29() {modrm_generateInstructionTEXT("SUBD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_SUB32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP2B() {modrm_generateInstructionTEXT("SUBD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_SUB32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP2D() {INLINEREGISTER uint_32 theimm = immw; modrm_generateInstructionTEXT("SUBD EAX,",0,theimm,PARAM_IMM16);/*5=AX,imm16*/ CPU80386_internal_SUB32(&REG_EAX,theimm,1);/*5=AX,imm16*/ }
void CPU80386_OP2F() {modrm_generateInstructionTEXT("DAS",0,0,PARAM_NONE);/*DAS?*/ CPU8086_internal_DAS();/*DAS?*/ }
void CPU80386_OP31() {modrm_generateInstructionTEXT("XORD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_XOR32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP33() {modrm_generateInstructionTEXT("XORD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_XOR32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP35() {INLINEREGISTER uint_32 theimm = immw; modrm_generateInstructionTEXT("XORD EAX,",0,theimm,PARAM_IMM16); CPU80386_internal_XOR32(&REG_EAX,theimm,1); }
void CPU80386_OP37() {modrm_generateInstructionTEXT("AAA",0,0,PARAM_NONE);/*AAA?*/ CPU80386_internal_AAA();/*AAA?*/ }
void CPU80386_OP39() {modrm_generateInstructionTEXT("CMPD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src0,1)) return; if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src0)) return; if (CPU80386_instructionstepreadmodrmdw(2,&instructionbufferd2,MODRM_src1)) return; CMP_dw(instructionbufferd,instructionbufferd2,2); }
void CPU80386_OP3B() {modrm_generateInstructionTEXT("CMPD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src0,1)) return; if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src0)) return; if (CPU80386_instructionstepreadmodrmdw(2,&instructionbufferd2,MODRM_src1)) return; CMP_dw(instructionbufferd,instructionbufferd2,2); }
void CPU80386_OP3D() {INLINEREGISTER word theimm = immw; modrm_generateInstructionTEXT("CMPD EAX,",0,theimm,PARAM_IMM16);/*CMP AX, imm16*/ CMP_dw(REG_EAX,theimm,1);/*CMP AX, imm16*/ }
void CPU80386_OP3F() {modrm_generateInstructionTEXT("AAS",0,0,PARAM_NONE);/*AAS?*/ CPU80386_internal_AAS();/*AAS?*/ }
void CPU80386_OP40() {modrm_generateInstructionTEXT("INC EAX",0,0,PARAM_NONE);/*INC EAX*/ CPU80386_internal_INC32(&REG_EAX);/*INC EAX*/ }
void CPU80386_OP41() {modrm_generateInstructionTEXT("INC ECX",0,0,PARAM_NONE);/*INC ECX*/ CPU80386_internal_INC32(&REG_ECX);/*INC ECX*/ }
void CPU80386_OP42() {modrm_generateInstructionTEXT("INC EDX",0,0,PARAM_NONE);/*INC EDX*/ CPU80386_internal_INC32(&REG_EDX);/*INC EDX*/ }
void CPU80386_OP43() {modrm_generateInstructionTEXT("INC EBX",0,0,PARAM_NONE);/*INC EBX*/ CPU80386_internal_INC32(&REG_EBX);/*INC EBX*/ }
void CPU80386_OP44() {modrm_generateInstructionTEXT("INC ESP",0,0,PARAM_NONE);/*INC ESP*/ CPU80386_internal_INC32(&REG_ESP);/*INC ESP*/ }
void CPU80386_OP45() {modrm_generateInstructionTEXT("INC EBP",0,0,PARAM_NONE);/*INC EBP*/ CPU80386_internal_INC32(&REG_EBP);/*INC EBP*/ }
void CPU80386_OP46() {modrm_generateInstructionTEXT("INC ESI",0,0,PARAM_NONE);/*INC ESI*/ CPU80386_internal_INC32(&REG_ESI);/*INC ESI*/ }
void CPU80386_OP47() {modrm_generateInstructionTEXT("INC EDI",0,0,PARAM_NONE);/*INC EDI*/ CPU80386_internal_INC32(&REG_EDI);/*INC EDI*/ }
void CPU80386_OP48() {modrm_generateInstructionTEXT("DEC EAX",0,0,PARAM_NONE);/*DEC EAX*/ CPU80386_internal_DEC32(&REG_EAX);/*DEC EAX*/ }
void CPU80386_OP49() {modrm_generateInstructionTEXT("DEC ECX",0,0,PARAM_NONE);/*DEC ECX*/ CPU80386_internal_DEC32(&REG_ECX);/*DEC ECX*/ }
void CPU80386_OP4A() {modrm_generateInstructionTEXT("DEC EDX",0,0,PARAM_NONE);/*DEC EDX*/ CPU80386_internal_DEC32(&REG_EDX);/*DEC EDX*/ }
void CPU80386_OP4B() {modrm_generateInstructionTEXT("DEC EBX",0,0,PARAM_NONE);/*DEC EBX*/ CPU80386_internal_DEC32(&REG_EBX);/*DEC EBX*/ }
void CPU80386_OP4C() {modrm_generateInstructionTEXT("DEC ESP",0,0,PARAM_NONE);/*DEC ESP*/ CPU80386_internal_DEC32(&REG_ESP);/*DEC ESP*/ }
void CPU80386_OP4D() {modrm_generateInstructionTEXT("DEC EBP",0,0,PARAM_NONE);/*DEC EBP*/ CPU80386_internal_DEC32(&REG_EBP);/*DEC EBP*/ }
void CPU80386_OP4E() {modrm_generateInstructionTEXT("DEC ESI",0,0,PARAM_NONE);/*DEC ESI*/ CPU80386_internal_DEC32(&REG_ESI);/*DEC ESI*/ }
void CPU80386_OP4F() {modrm_generateInstructionTEXT("DEC EDI",0,0,PARAM_NONE);/*DEC EDI*/ CPU80386_internal_DEC32(&REG_EDI);/*DEC EDI*/ }
void CPU80386_OP50() {modrm_generateInstructionTEXT("PUSH EAX",0,0,PARAM_NONE);/*PUSH EAX*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,1,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_PUSHdw(0,&REG_EAX)) return; /*PUSH AX*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 11-EU_CYCLES_SUBSTRACT_ACCESSWRITE; /*Push Reg!*/ } }
void CPU80386_OP51() {modrm_generateInstructionTEXT("PUSH ECX",0,0,PARAM_NONE);/*PUSH ECX*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,1,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_PUSHdw(0,&REG_ECX)) return; /*PUSH CX*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 11-EU_CYCLES_SUBSTRACT_ACCESSWRITE; /*Push Reg!*/ } }
void CPU80386_OP52() {modrm_generateInstructionTEXT("PUSH EDX",0,0,PARAM_NONE);/*PUSH EDX*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,1,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_PUSHdw(0,&REG_EDX)) return; /*PUSH DX*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 11-EU_CYCLES_SUBSTRACT_ACCESSWRITE; /*Push Reg!*/ } }
void CPU80386_OP53() {modrm_generateInstructionTEXT("PUSH EBX",0,0,PARAM_NONE);/*PUSH EBX*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,1,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_PUSHdw(0,&REG_EBX)) return; /*PUSH BX*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 11-EU_CYCLES_SUBSTRACT_ACCESSWRITE; /*Push Reg!*/ } }
void CPU80386_OP54() {modrm_generateInstructionTEXT("PUSH ESP",0,0,PARAM_NONE);/*PUSH ESP*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,1,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_PUSHdw(0,&REG_ESP)) return; /*PUSH SP*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 11-EU_CYCLES_SUBSTRACT_ACCESSWRITE; /*Push Reg!*/ } }
void CPU80386_OP55() {modrm_generateInstructionTEXT("PUSH EBP",0,0,PARAM_NONE);/*PUSH EBP*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,1,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_PUSHdw(0,&REG_EBP)) return; /*PUSH BP*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 11-EU_CYCLES_SUBSTRACT_ACCESSWRITE; /*Push Reg!*/ } }
void CPU80386_OP56() {modrm_generateInstructionTEXT("PUSH ESI",0,0,PARAM_NONE);/*PUSH ESI*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,1,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_PUSHdw(0,&REG_ESI)) return; /*PUSH SI*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 11-EU_CYCLES_SUBSTRACT_ACCESSWRITE; /*Push Reg!*/ } }
void CPU80386_OP57() {modrm_generateInstructionTEXT("PUSH EDI",0,0,PARAM_NONE);/*PUSH EDI*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,1,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_PUSHdw(0,&REG_EDI)) return; /*PUSH DI*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 11-EU_CYCLES_SUBSTRACT_ACCESSWRITE; /*Push Reg!*/ } }
void CPU80386_OP58() {modrm_generateInstructionTEXT("POP EAX",0,0,PARAM_NONE);/*POP EAX*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,0,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_instructionstepPOPtimeout(0)) return; /*POP timeout*/ if (CPU80386_POPdw(2,&REG_EAX)) return; /*POP AX*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; /*Pop Reg!*/ } }
void CPU80386_OP59() {modrm_generateInstructionTEXT("POP ECX",0,0,PARAM_NONE);/*POP ECX*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,0,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_instructionstepPOPtimeout(0)) return; /*POP timeout*/ if (CPU80386_POPdw(2,&REG_ECX)) return; /*POP CX*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; /*Pop Reg!*/ } }
void CPU80386_OP5A() {modrm_generateInstructionTEXT("POP EDX",0,0,PARAM_NONE);/*POP EDX*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,0,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_instructionstepPOPtimeout(0)) return; /*POP timeout*/ if (CPU80386_POPdw(2,&REG_EDX)) return; /*POP DX*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; /*Pop Reg!*/ } }
void CPU80386_OP5B() {modrm_generateInstructionTEXT("POP EBX",0,0,PARAM_NONE);/*POP EBX*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,0,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_instructionstepPOPtimeout(0)) return; /*POP timeout*/ if (CPU80386_POPdw(2,&REG_EBX)) return; /*POP BX*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; /*Pop Reg!*/ } }
void CPU80386_OP5C() {modrm_generateInstructionTEXT("POP ESP",0,0,PARAM_NONE);/*POP ESP*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,0,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_instructionstepPOPtimeout(0)) return; /*POP timeout*/ if (CPU80386_POPESP(2)) return; /*POP SP*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; /*Pop Reg!*/ } }
void CPU80386_OP5D() {modrm_generateInstructionTEXT("POP EBP",0,0,PARAM_NONE);/*POP EBP*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,0,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_instructionstepPOPtimeout(0)) return; /*POP timeout*/ if (CPU80386_POPdw(2,&REG_EBP)) return; /*POP BP*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; /*Pop Reg!*/ } }
void CPU80386_OP5E() {modrm_generateInstructionTEXT("POP ESI",0,0,PARAM_NONE);/*POP ESI*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,0,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_instructionstepPOPtimeout(0)) return; /*POP timeout*/ if (CPU80386_POPdw(2,&REG_ESI)) return;/*POP SI*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; /*Pop Reg!*/ } }
void CPU80386_OP5F() {modrm_generateInstructionTEXT("POP EDI",0,0,PARAM_NONE);/*POP EDI*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,0,0)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_instructionstepPOPtimeout(0)) return; /*POP timeout*/ if (CPU80386_POPdw(2,&REG_EDI)) return;/*POP DI*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; /*Pop Reg!*/ } }
void CPU80386_OP85() {modrm_generateInstructionTEXT("TESTD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src0,1)) return; if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src0)) return; if (CPU80386_instructionstepreadmodrmdw(2,&instructionbufferd2,MODRM_src1)) return; CPU80386_internal_TEST32(instructionbufferd,instructionbufferd2,2); }
void CPU80386_OP87() {modrm_generateInstructionTEXT("XCHGD",32,0,PARAM_MODRM_01); CPU80386_internal_XCHG32(modrm_addr32(&params,MODRM_src0,0),modrm_addr32(&params,MODRM_src1,0),2); /*XCHG reg32,r/m32*/ }
void CPU80386_OP89() {modrm_generateInstructionTEXT("MOVD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_MOV32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP8B() {modrm_generateInstructionTEXT("MOVD",32,0,PARAM_MODRM_01); if (modrm_check32(&params,MODRM_src1,1)) return; if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_internal_MOV32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,2); }
void CPU80386_OP8D() {modrm_debugger32(&params,MODRM_src0,MODRM_src1); debugger_setcommand("LEAD %s,%s",modrm_param1,getLEAtext32(&params)); if (CPU80386_internal_MOV32(modrm_addr32(&params,MODRM_src0,0),getLEA32(&params),0)) return; if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{  CPU[activeCPU].cycles_OP += 2; /* Load effective address */ } }
void CPU80386_OP90() /*NOP*/ {modrm_generateInstructionTEXT("NOP",0,0,PARAM_NONE);/*NOP (XCHG EAX,EAX)*/ if (CPU80386_internal_XCHG32(&REG_EAX,&REG_EAX,1)) return; /* NOP */}
void CPU80386_OP91() {modrm_generateInstructionTEXT("XCHG ECX,EAX",0,0,PARAM_NONE);/*XCHG ECX,EAX*/ CPU80386_internal_XCHG32(&REG_ECX,&REG_EAX,1); /*XCHG CX,AX*/ }
void CPU80386_OP92() {modrm_generateInstructionTEXT("XCHG EDX,EAX",0,0,PARAM_NONE);/*XCHG EDX,EAX*/ CPU80386_internal_XCHG32(&REG_EDX,&REG_EAX,1); /*XCHG DX,AX*/ }
void CPU80386_OP93() {modrm_generateInstructionTEXT("XCHG EBX,EAX",0,0,PARAM_NONE);/*XCHG EBX,EAX*/ CPU80386_internal_XCHG32(&REG_EBX,&REG_EAX,1); /*XCHG BX,AX*/ }
void CPU80386_OP94() {modrm_generateInstructionTEXT("XCHG ESP,EAX",0,0,PARAM_NONE);/*XCHG ESP,EAX*/ CPU80386_internal_XCHG32(&REG_ESP,&REG_EAX,1); /*XCHG SP,AX*/ }
void CPU80386_OP95() {modrm_generateInstructionTEXT("XCHG EBP,EAX",0,0,PARAM_NONE);/*XCHG EBP,EAX*/ CPU80386_internal_XCHG32(&REG_EBP,&REG_EAX,1); /*XCHG BP,AX*/ }
void CPU80386_OP96() {modrm_generateInstructionTEXT("XCHG ESI,EAX",0,0,PARAM_NONE);/*XCHG ESI,EAX*/ CPU80386_internal_XCHG32(&REG_ESI,&REG_EAX,1); /*XCHG SI,AX*/ }
void CPU80386_OP97() {modrm_generateInstructionTEXT("XCHG EDI,EAX",0,0,PARAM_NONE);/*XCHG EDI,EAX*/ CPU80386_internal_XCHG32(&REG_EDI,&REG_EAX,1); /*XCHG DI,AX*/ }
void CPU80386_OP98() {modrm_generateInstructionTEXT("CWDE",0,0,PARAM_NONE);/*CWDE : sign extend AX to EAX*/ CPU80386_internal_CWDE();/*CWDE : sign extend AX to EAX (80386+)*/ }
void CPU80386_OP99() {modrm_generateInstructionTEXT("CDQ",0,0,PARAM_NONE);/*CDQ : sign extend EAX to EDX::EAX*/ CPU80386_internal_CDQ();/*CWQ : sign extend EAX to EDX::EAX (80386+)*/ }
void CPU80386_OP9A() {/*CALL Ap*/ INLINEREGISTER uint_64 segmentoffset = imm64; debugger_setcommand("CALL %04x:%08x", (segmentoffset>>32), (segmentoffset&CPU_EIPmask())); CPU80386_CALLF((segmentoffset>>32)&0xFFFF,segmentoffset&CPU_EIPmask()); if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 28; /* Intersegment direct */ } }

//END OF BLOCK CONVERTED TO 80386 FROM 8086

//TODO: cycle accurate version of new PUSHFD/POPF/POPFD
void CPU80386_OP9C() {modrm_generateInstructionTEXT("PUSHFD",0,0,PARAM_NONE);/*PUSHF*/ if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,1,1)) return; ++CPU[activeCPU].stackchecked; } uint_32 flags = REG_EFLAGS; if (FLAG_V8) flags &=~0x20000; /* VM is never pushed during Virtual 8086 mode! */ if (CPU80386_PUSHdw(0,&flags)) return; if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSWRITE; /*PUSHF timing!*/ } }

void CPU80386_OP9D_16() {
	modrm_generateInstructionTEXT("POPF", 0, 0, PARAM_NONE);/*POPF*/
	if ((getcpumode()==CPU_MODE_8086) && (FLAG_PL!=3)) THROWDESCGP(0,0,0); //#GP fault!
	static word tempflags;
	if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,0,0)) return; ++CPU[activeCPU].stackchecked; }
	if (CPU80386_instructionstepPOPtimeout(0)) return; /*POP timeout*/
	if (CPU8086_POPw(2,&tempflags)) return;
	if (disallowPOPFI()) { tempflags &= ~0x200; tempflags |= REG_FLAGS&0x200; /* Ignore any changes to the Interrupt flag! */ }
	if (getCPL()) { tempflags &= ~0x3000; tempflags |= REG_FLAGS&0x3000; /* Ignore any changes to the IOPL when not at CPL 0! */ }
	REG_FLAGS = tempflags;
	updateCPUmode(); /*POPF*/
	if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{  CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; /*POPF timing!*/ }
	CPU[activeCPU].allowTF = 0; /*Disallow TF to be triggered after the instruction!*/
}

void CPU80386_OP9D_32() {
	modrm_generateInstructionTEXT("POPFD", 0, 0, PARAM_NONE);/*POPF*/
	if ((getcpumode()==CPU_MODE_8086) && (FLAG_PL!=3)) THROWDESCGP(0,0,0); //#GP fault!
	static uint_32 tempflags;
	if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,0,1)) return; ++CPU[activeCPU].stackchecked; }
	if (CPU80386_instructionstepPOPtimeout(0)) return; /*POP timeout*/
	if (CPU80386_POPdw(2,&tempflags)) return;
	if (disallowPOPFI()) { tempflags &= ~0x200; tempflags |= REG_FLAGS&0x200; /* Ignore any changes to the Interrupt flag! */ }
	if (getcpumode()==CPU_MODE_8086) //Virtual 8086 mode?
	{
		if (FLAG_PL==3) //IOPL 3?
		{
			tempflags = ((tempflags&~0x3000)|(REG_EFLAGS&0x3000)); /* Ignore any changes to the VM, RF, IOPL, VIP and VIF ! */
		} //Otherwise, fault is raised!
	}
	else //Protected/real mode?
	{
		if (getCPL())
		{
			tempflags = ((tempflags&~0x1A3000)|(REG_EFLAGS&0x23000)); /* Ignore any changes to the IOPL, VM ! VIP/VIF are cleared. */			
		}
		else
		{
			tempflags = ((tempflags&~0x1A0000)|(REG_EFLAGS&0x20000)); /* Ignore any changes to the VIP/VIF are cleared. Ignore any changes to VM! */			
		}
	}
	REG_EFLAGS = tempflags;
	updateCPUmode(); /*POPF*/
	if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{  CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; /*POPF timing!*/ }
	CPU[activeCPU].allowTF = 0; /*Disallow TF to be triggered after the instruction!*/
}

//Different addressing modes affect us! Combine operand size and address size into new versions of the instructions, where needed!
//16/32 depending on address size!
//A0 32-bits address version with 8-bit reg
OPTINLINE void CPU80386_OPA0_8exec_addr32() {debugger_setcommand("MOVB AL,[%s:%08X]",CPU_textsegment(CPU_SEGMENT_DS),immaddr32);/*MOV AL,[imm32]*/ if (CPU[activeCPU].internalinstructionstep==0) { if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32,1,getCPL(),!CPU_Address_size[activeCPU],0)) return; } if (CPU8086_internal_stepreaddirectb(0,CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32,&instructionbufferb,0)) return; CPU80386_internal_MOV8(&REG_AL,instructionbufferb,1);/*MOV AL,[imm32]*/ }

//A1 16/32-bits address version with 16/32-bit reg
OPTINLINE void CPU80386_OPA1_16exec_addr32() {debugger_setcommand("MOVW AX,[%s:%08X]",CPU_textsegment(CPU_SEGMENT_DS),immaddr32);/*MOV AX,[imm32]*/ if (CPU[activeCPU].internalinstructionstep==0) { if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32,1,getCPL(),!CPU_Address_size[activeCPU],0|0x8)) return; if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32+1,1,getCPL(),!CPU_Address_size[activeCPU],1|0x8)) return; } if (CPU8086_internal_stepreaddirectw(0,CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32,&instructionbufferw,0)) return; CPU80386_internal_MOV16(&REG_AX,instructionbufferw,1);/*MOV AX,[imm32]*/ }
OPTINLINE void CPU80386_OPA1_32exec_addr16() {debugger_setcommand("MOVD EAX,[%s:%04X]",CPU_textsegment(CPU_SEGMENT_DS),immaddr32);/*MOV AX,[imm32]*/ if (CPU[activeCPU].internalinstructionstep==0) { if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32,1,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) return; if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32+1,1,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) return; if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32+2,1,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) return; if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32+3,1,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) return; } if (CPU80386_internal_stepreaddirectdw(0,CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32,&instructionbufferd,1)) return; CPU80386_internal_MOV32(&REG_EAX,instructionbufferd,1);/*MOV EAX,[imm16]*/ }
OPTINLINE void CPU80386_OPA1_32exec_addr32() {debugger_setcommand("MOVD EAX,[%s:%08X]",CPU_textsegment(CPU_SEGMENT_DS),immaddr32);/*MOV AX,[imm32]*/ if (CPU[activeCPU].internalinstructionstep==0) { if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32,1,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) return; if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32+1,1,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) return; if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32+2,1,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) return; if (checkMMUaccess(CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32+3,1,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) return; } if (CPU80386_internal_stepreaddirectdw(0,CPU_segment_index(CPU_SEGMENT_DS),CPU_segment(CPU_SEGMENT_DS),immaddr32,&instructionbufferd,1)) return; CPU80386_internal_MOV32(&REG_EAX,instructionbufferd,1);/*MOV EAX,[imm32]*/ }

//A2 32-bits address version with 8-bit reg
OPTINLINE void CPU80386_OPA2_8exec_addr32() {debugger_setcommand("MOVB [%s:%08X],AL",CPU_textsegment(CPU_SEGMENT_DS),immaddr32);/*MOV [imm32],AL*/ custommem = 1; customoffset = immaddr32; CPU80386_internal_MOV8(NULL,REG_AL,1);/*MOV [imm32],AL*/ custommem = 0; }

//A3 16/32-bits address version with 16/32-bit reg
OPTINLINE void CPU80386_OPA3_16exec_addr32() {debugger_setcommand("MOVW [%s:%08X],AX",CPU_textsegment(CPU_SEGMENT_DS),immaddr32);/*MOV [imm32], AX*/ custommem = 1; customoffset = immaddr32; CPU80386_internal_MOV16(NULL,REG_AX,1);/*MOV [imm32], AX*/ custommem = 0; }
OPTINLINE void CPU80386_OPA3_32exec_addr16() {debugger_setcommand("MOVD [%s:%04X],EAX",CPU_textsegment(CPU_SEGMENT_DS),immaddr32);/*MOV [imm32], AX*/ custommem = 1; customoffset = immaddr32; CPU80386_internal_MOV32(NULL,REG_EAX,1);/*MOV [imm32], AX*/ custommem = 0; }
OPTINLINE void CPU80386_OPA3_32exec_addr32() {debugger_setcommand("MOVD [%s:%08X],EAX",CPU_textsegment(CPU_SEGMENT_DS),immaddr32);/*MOV [imm32], AX*/ custommem = 1; customoffset = immaddr32; CPU80386_internal_MOV32(NULL,REG_EAX,1);/*MOV [imm32], AX*/ custommem = 0; }

//Our two calling methods for handling the jumptable!
//16-bits versions having a new 32-bit address size override!
void CPU80386_OPA0_16() {if (CPU_Address_size[activeCPU]) CPU80386_OPA0_8exec_addr32(); else CPU8086_OPA0();}
void CPU80386_OPA1_16() {if (CPU_Address_size[activeCPU]) CPU80386_OPA1_16exec_addr32(); else CPU8086_OPA1();}
void CPU80386_OPA2_16() {if (CPU_Address_size[activeCPU]) CPU80386_OPA2_8exec_addr32(); else CPU8086_OPA2();}
void CPU80386_OPA3_16() {if (CPU_Address_size[activeCPU]) CPU80386_OPA3_16exec_addr32(); else CPU8086_OPA3();}
//32-bits versions having a new 32-bit address size override and operand size override, except 8-bit instructions!
void CPU80386_OPA1_32() {if (CPU_Address_size[activeCPU]) CPU80386_OPA1_32exec_addr32(); else CPU80386_OPA1_32exec_addr16();}
void CPU80386_OPA3_32() {if (CPU_Address_size[activeCPU]) CPU80386_OPA3_32exec_addr32(); else CPU80386_OPA3_32exec_addr16();}

//Normal instruction again!
void CPU80386_OPA5() {modrm_generateInstructionTEXT("MOVSD",0,0,PARAM_NONE);/*MOVSD*/ CPU80386_internal_MOVSD();/*MOVSD*/ }
void CPU80386_OPA7() {debugger_setcommand(CPU_Address_size[activeCPU]?"CMPSD [%s:ESI],[ES:EDI]":"CMPSD [%s:SI],[ES:DI]",CPU_textsegment(CPU_SEGMENT_DS));/*CMPSD*/ CPU80386_internal_CMPSD();/*CMPSD*/ }
void CPU80386_OPA9() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("TESTD EAX,",0,theimm,PARAM_IMM32);/*TEST EAX,imm32*/ CPU80386_internal_TEST32(REG_EAX,theimm,1);/*TEST EAX,imm32*/ }
void CPU80386_OPAB() {modrm_generateInstructionTEXT("STOSD",0,0,PARAM_NONE);/*STOSW*/ CPU80386_internal_STOSD();/*STOSW*/ }
void CPU80386_OPAD() {modrm_generateInstructionTEXT("LODSD",0,0,PARAM_NONE);/*LODSW*/ CPU80386_internal_LODSD();/*LODSW*/ }
void CPU80386_OPAF() {modrm_generateInstructionTEXT("SCASD",0,0,PARAM_NONE);/*SCASW*/ CPU80386_internal_SCASD();/*SCASW*/ }
void CPU80386_OPB8() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("MOVD EAX,",0,theimm,PARAM_IMM32);/*MOV AX,imm32*/ CPU80386_internal_MOV32(&REG_EAX,theimm,4);/*MOV AX,imm32*/ }
void CPU80386_OPB9() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("MOVD ECX,",0,theimm,PARAM_IMM32);/*MOV CX,imm32*/ CPU80386_internal_MOV32(&REG_ECX,theimm,4);/*MOV CX,imm32*/ }
void CPU80386_OPBA() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("MOVD EDX,",0,theimm,PARAM_IMM32);/*MOV DX,imm32*/ CPU80386_internal_MOV32(&REG_EDX,theimm,4);/*MOV DX,imm32*/ }
void CPU80386_OPBB() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("MOVD EBX,",0,theimm,PARAM_IMM32);/*MOV BX,imm32*/ CPU80386_internal_MOV32(&REG_EBX,theimm,4);/*MOV BX,imm32*/ }
void CPU80386_OPBC() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("MOVD ESP,",0,theimm,PARAM_IMM32);/*MOV SP,imm32*/ CPU80386_internal_MOV32(&REG_ESP,theimm,4);/*MOV SP,imm32*/ }
void CPU80386_OPBD() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("MOVD EBP,",0,theimm,PARAM_IMM32);/*MOV BP,imm32*/ CPU80386_internal_MOV32(&REG_EBP,theimm,4);/*MOV BP,imm32*/ }
void CPU80386_OPBE() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("MOVD ESI,",0,theimm,PARAM_IMM32);/*MOV SI,imm32*/ CPU80386_internal_MOV32(&REG_ESI,theimm,4);/*MOV SI,imm32*/ }
void CPU80386_OPBF() {INLINEREGISTER uint_32 theimm = imm32; modrm_generateInstructionTEXT("MOVD EDI,",0,theimm,PARAM_IMM32);/*MOV DI,imm32*/ CPU80386_internal_MOV32(&REG_EDI,theimm,4);/*MOV DI,imm32*/ }
void CPU80386_OPC2() {INLINEREGISTER int_32 popbytes = imm32();/*RET imm32 (Near return to calling proc and POP imm32 bytes)*/ modrm_generateInstructionTEXT("RET",0,popbytes,PARAM_IMM8); /*RET imm32 (Near return to calling proc and POP imm32 bytes)*/ CPU80386_internal_RET(popbytes,1); }
void CPU80386_OPC3() {modrm_generateInstructionTEXT("RET",0,0,PARAM_NONE);/*RET (Near return to calling proc)*/ /*RET (Near return to calling proc)*/ CPU80386_internal_RET(0,0); }
void CPU80386_OPC4() /*LES modr/m*/ {modrm_generateInstructionTEXT("LES",0,0,PARAM_MODRM_01); CPU80386_internal_LXS(CPU_SEGMENT_ES); /*Load new ES!*/ }
void CPU80386_OPC5() /*LDS modr/m*/ {modrm_generateInstructionTEXT("LDS",0,0,PARAM_MODRM_01); CPU80386_internal_LXS(CPU_SEGMENT_DS); /*Load new DS!*/ }
void CPU80386_OPC7() {uint_32 val = immw; modrm_debugger32(&params,MODRM_src0,MODRM_src1); debugger_setcommand("MOVD %s,%08x",modrm_param1,val); if (modrm_check32(&params,MODRM_src0,0)) return; if (CPU80386_instructionstepwritemodrmdw(0,val,MODRM_src0)) return; if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ if (MODRM_EA(params)) { CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSWRITE; /* Imm->Mem */ } else CPU[activeCPU].cycles_OP += 4; /* Imm->Reg */ } }
void CPU80386_OPCA() {INLINEREGISTER word popbytes = immw;/*RETF imm32 (Far return to calling proc and pop imm32 bytes)*/ modrm_generateInstructionTEXT("RETF",0,popbytes,PARAM_IMM32); /*RETF imm32 (Far return to calling proc and pop imm16 bytes)*/ CPU80386_internal_RETF(popbytes,1); }
void CPU80386_OPCB() {modrm_generateInstructionTEXT("RETF",0,0,PARAM_NONE); /*RETF (Far return to calling proc)*/ CPU80386_internal_RETF(0,0); }
void CPU80386_OPCC() {modrm_generateInstructionTEXT("INT 3",0,0,PARAM_NONE); /*INT 3*/ if (isV86() && (FLAG_PL!=3)) {THROWDESCGP(0,0,0); return; } if (CPU_faultraised(EXCEPTION_CPUBREAKPOINT)) { CPU80386_INTERNAL_int(EXCEPTION_CPUBREAKPOINT,1); } /*INT 3*/ }
void CPU80386_OPCD() {INLINEREGISTER byte theimm = immb; INTdebugger80386();  modrm_generateInstructionTEXT("INT",0,theimm,PARAM_IMM8);/*INT imm8*/ if (isV86() && (FLAG_PL!=3)) {THROWDESCGP(0,0,0); return; } CPU80386_INTERNAL_int(theimm,0);/*INT imm8*/ }
void CPU80386_OPCE() {modrm_generateInstructionTEXT("INTO",0,0,PARAM_NONE);/*INTO*/ if (isV86() && (FLAG_PL!=3)) {THROWDESCGP(0,0,0); return; } CPU80386_internal_INTO();/*INTO*/ }
void CPU80386_OPCF() {modrm_generateInstructionTEXT("IRET",0,0,PARAM_NONE);/*IRET*/ if (isV86() && (FLAG_PL!=3)) {THROWDESCGP(0,0,0); return; } CPU80386_IRET();/*IRET : also restore interrupt flag!*/ }
void CPU80386_OPD4() {INLINEREGISTER byte theimm = immb; modrm_generateInstructionTEXT("AAM",0,theimm,PARAM_IMM8);/*AAM*/ CPU80386_internal_AAM(theimm);/*AAM*/ }
void CPU80386_OPD5() {INLINEREGISTER byte theimm = immb; modrm_generateInstructionTEXT("AAD",0,theimm,PARAM_IMM8);/*AAD*/ CPU80386_internal_AAD(theimm);/*AAD*/ }
void CPU80386_OPD6(){debugger_setcommand("SALC"); REG_AL=FLAG_CF?0xFF:0x00; if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 2; } } //Special case on the 80386: SALC!
void CPU80386_OPD7(){CPU80386_internal_XLAT();} //We depend on the address size instead!
void CPU80386_OPE0(){INLINEREGISTER sbyte rel8; rel8 = imm8(); modrm_generateInstructionTEXT("LOOPNZ",0, ((REG_EIP+rel8)&CPU_EIPmask()),CPU_EIPSize()); if ((--REG_ECX) && (!FLAG_ZF)){CPU_JMPrel(rel8); CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 19; } /* Branch taken */} else { if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 5; } /* Branch not taken */}}
void CPU80386_OPE1(){INLINEREGISTER sbyte rel8; rel8 = imm8(); modrm_generateInstructionTEXT("LOOPZ",0, ((REG_EIP+rel8)&CPU_EIPmask()),CPU_EIPSize());if ((--REG_ECX) && (FLAG_ZF)){CPU_JMPrel(rel8);CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{  CPU[activeCPU].cycles_OP += 18; } /* Branch taken */} else { if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 6; } /* Branch not taken */}}
void CPU80386_OPE2(){INLINEREGISTER sbyte rel8; rel8 = imm8(); modrm_generateInstructionTEXT("LOOP", 0,((REG_EIP+rel8)&CPU_EIPmask()),CPU_EIPSize());if (--REG_ECX){CPU_JMPrel(rel8);CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 17; } /* Branch taken */} else { if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 5; } /* Branch not taken */}}
void CPU80386_OPE3(){INLINEREGISTER sbyte rel8; rel8 = imm8(); modrm_generateInstructionTEXT("JCXZ",0,((REG_EIP+rel8)&CPU_EIPmask()),CPU_EIPSize()); if (!REG_ECX){CPU_JMPrel(rel8);CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 18; }  /* Branch taken */} else { if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 6; } /* Branch not taken */}}
void CPU80386_OPE5(){INLINEREGISTER byte theimm = immb;modrm_generateInstructionTEXT("IN EAX,",0,theimm,PARAM_IMM8); if (CPU_PORT_IN_D(0,theimm,&REG_EAX)) return; if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSREAD; /*Timings!*/ } }
void CPU80386_OPE7(){INLINEREGISTER byte theimm = immb; debugger_setcommand("OUT %02X,EAX",theimm); if (CPU_PORT_OUT_D(0,theimm,REG_EAX)) return; if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 10-EU_CYCLES_SUBSTRACT_ACCESSWRITE; /*Timings!*/ } }
void CPU80386_OPE8(){INLINEREGISTER int_32 reloffset = imm32(); modrm_generateInstructionTEXT("CALL",0,((REG_EIP + reloffset)&CPU_EIPmask()),CPU_EIPSize()); if (CPU[activeCPU].stackchecked==0) { if (checkStackAccess(1,1,1)) return; ++CPU[activeCPU].stackchecked; } if (CPU80386_PUSHdw(0,&REG_EIP)) return; CPU_JMPrel(reloffset);CPU_flushPIQ(-1); /*We're jumping to another address*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 19-EU_CYCLES_SUBSTRACT_ACCESSREAD; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Intrasegment direct */}
void CPU80386_OPE9(){INLINEREGISTER int_32 reloffset = imm32(); modrm_generateInstructionTEXT("JMP",0,((REG_EIP + reloffset)&CPU_EIPmask()),CPU_EIPSize()); CPU_JMPrel(reloffset);CPU_flushPIQ(-1); /*We're jumping to another address*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 15; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Intrasegment direct */}
void CPU80386_OPEA(){INLINEREGISTER uint_64 segmentoffset = imm64; debugger_setcommand("JMP %04X:%08X", (segmentoffset>>32), (segmentoffset&CPU_EIPmask())); destEIP = (segmentoffset&CPU_EIPmask()); segmentWritten(CPU_SEGMENT_CS, (word)(segmentoffset>>32), 1); CPU_flushPIQ(-1); if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 15; } /* Intersegment direct */}
void CPU80386_OPEB(){INLINEREGISTER sbyte reloffset = imm8(); modrm_generateInstructionTEXT("JMP",0,((REG_EIP + reloffset)&CPU_EIPmask()),CPU_EIPSize()); CPU_JMPrel(reloffset);CPU_flushPIQ(-1); /*We're jumping to another address*/ if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 15; CPU[activeCPU].cycles_stallBIU += 6; /*Stall the BIU partly now!*/ } /* Intrasegment direct short */}
void CPU80386_OPED(){modrm_generateInstructionTEXT("IN EAX,DX",0,0,PARAM_NONE); if (CPU_PORT_IN_D(0,REG_DX,&REG_EAX)) return; if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSREAD; /*Timings!*/ } }
void CPU80386_OPEF(){modrm_generateInstructionTEXT("OUT DX,EAX",0,0,PARAM_NONE); if (CPU_PORT_OUT_D(0,REG_DX,REG_EAX)) return; if (CPU_apply286cycles()==0) /* No 80286+ cycles instead? */{ CPU[activeCPU].cycles_OP += 8-EU_CYCLES_SUBSTRACT_ACCESSWRITE; /*Timings!*/ } /*To memory?*/}
void CPU80386_OPF1(){modrm_generateInstructionTEXT("<Undefined and reserved opcode, no error>",0,0,PARAM_NONE);}

/*

NOW COME THE GRP1-5 OPCODES:

*/

//GRP1

/*

DEBUG: REALLY SUPPOSED TO HANDLE OP80-83 HERE?

*/

void CPU80386_OP81() //GRP1 Ev,Iv
{
	INLINEREGISTER uint_32 imm = imm32;
	if (cpudebugger) //Debugger on?
	{
		modrm_debugger32(&params,1,0);
	}
	switch (MODRM_REG(params.modrm)) //What function?
	{
	case 0: //ADD
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("ADDD %s,%04X",&modrm_param1,imm); //ADD Eb, Ib
		}
		CPU80386_internal_ADD32(modrm_addr32(&params,1,0),imm,3); //ADD Eb, Ib
		break;
	case 1: //OR
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("ORD %s,%04X",&modrm_param1,imm); //OR Eb, Ib
		}
		CPU80386_internal_OR32(modrm_addr32(&params,1,0),imm,3); //OR Eb, Ib
		break;
	case 2: //ADC
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("ADCD %s,%04X",&modrm_param1,imm); //ADC Eb, Ib
		}
		CPU80386_internal_ADC32(modrm_addr32(&params,1,0),imm,3); //ADC Eb, Ib
		break;
	case 3: //SBB
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("SBBD %s,%04X",&modrm_param1,imm); //SBB Eb, Ib
		}
		CPU80386_internal_SBB32(modrm_addr32(&params,1,0),imm,3); //SBB Eb, Ib
		break;
	case 4: //AND
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("ANDD %s,%04X",&modrm_param1,imm); //AND Eb, Ib
		}
		CPU80386_internal_AND32(modrm_addr32(&params,1,0),imm,3); //AND Eb, Ib
		break;
	case 5: //SUB
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("SUBD %s,%04X",&modrm_param1,imm); //SUB Eb, Ib
		}
		CPU80386_internal_SUB32(modrm_addr32(&params,1,0),imm,3); //SUB Eb, Ib
		break;
	case 6: //XOR
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("XORD %s,%04X",&modrm_param1,imm); //XOR Eb, Ib
		}
		CPU80386_internal_XOR32(modrm_addr32(&params,1,0),imm,3); //XOR Eb, Ib
		break;
	case 7: //CMP
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("CMPD %s,%04X",&modrm_param1,imm); //CMP Eb, Ib
		}
		if (modrm_check32(&params,1,1)) return; //Abort when needed!
		CMP_dw(modrm_read32(&params,1),imm,3); //CMP Eb, Ib
		break;
	default:
		break;
	}
}

void CPU80386_OP83() //GRP1 Ev,Ib
{
	INLINEREGISTER uint_32 imm;
	imm = immb;
	if (imm&0x80) imm |= 0xFFFFFF00; //Sign extend!
	if (cpudebugger) //Debugger on?
	{
		modrm_debugger32(&params,1,0);
	}
	switch (MODRM_REG(params.modrm)) //What function?
	{
	case 0: //ADD
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("ADDD %s,%04X",&modrm_param1,imm); //ADD Eb, Ib
		}
		CPU80386_internal_ADD32(modrm_addr32(&params,1,0),imm,3); //ADD Eb, Ib
		break;
	case 1: //OR
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("ORD %s,%04X",&modrm_param1,imm); //OR Eb, Ib
		}
		CPU80386_internal_OR32(modrm_addr32(&params,1,0),imm,3); //OR Eb, Ib
		break;
	case 2: //ADC
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("ADCD %s,%04X",&modrm_param1,imm); //ADC Eb, Ib
		}
		CPU80386_internal_ADC32(modrm_addr32(&params,1,0),imm,3); //ADC Eb, Ib
		break;
	case 3: //SBB
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("SBBD %s,%04X",&modrm_param1,imm); //SBB Eb, Ib
		}
		CPU80386_internal_SBB32(modrm_addr32(&params,1,0),imm,3); //SBB Eb, Ib
		break;
	case 4: //AND
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("ANDD %s,%04X",&modrm_param1,imm); //AND Eb, Ib
		}
		CPU80386_internal_AND32(modrm_addr32(&params,1,0),imm,3); //AND Eb, Ib
		break;
	case 5: //SUB
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("SUBD %s,%04X",&modrm_param1,imm); //SUB Eb, Ib
		}
		CPU80386_internal_SUB32(modrm_addr32(&params,1,0),imm,3); //SUB Eb, Ib
		break;
	case 6: //XOR
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("XORD %s,%04X",&modrm_param1,imm); //XOR Eb, Ib
		}
		CPU80386_internal_XOR32(modrm_addr32(&params,1,0),imm,3); //XOR Eb, Ib
		break;
	case 7: //CMP
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("CMPD %s,%04X",&modrm_param1,imm); //CMP Eb, Ib
		}
		if (modrm_check32(&params,1,1)) return; //Abort when needed!
		CMP_dw(modrm_read32(&params,1),imm,3); //CMP Eb, Ib
		break;
	default:
		break;
	}
}

void CPU80386_OP8F() //Undocumented GRP opcode 8F r/m32
{
	if (cpudebugger)
	{
		modrm_debugger32(&params,0,1);
	}
	switch (MODRM_REG(params.modrm)) //What function?
	{
	case 0: //POP
		if (cpudebugger) //Debugger on?
		{
			modrm_generateInstructionTEXT("POPD",32,0,PARAM_MODRM2); //POPD Ew
		}
		if (checkStackAccess(1,0,1)) return; //Abort when needed!
		if (modrm_check32(&params,1,0)) return; //Abort when needed!
		modrm_write32(&params,1,CPU_POP32()); //POP r/m32
		if (MODRM_EA(params)) //Mem?
		{
			CPU[activeCPU].cycles_OP = 17+MODRM_EA(params); /*Pop Mem!*/
		}
		else //Reg?
		{
			CPU[activeCPU].cycles_OP = 8; /*Pop Reg!*/
		}
		break;
	default: //Unknown opcode or special?
		if (cpudebugger) //Debugger on?
		{
			debugger_setcommand("Unknown opcode: 8F /%i",MODRM_REG(params.modrm)); //Error!
		}
		CPU_unkOP(); //Execute the unknown opcode exception handler, if any!
		break;
	}
}

void CPU80386_OPD1() //GRP2 Ev,1
{
	thereg = MODRM_REG(params.modrm);
	if (modrm_check32(&params,1,1)) return; //Abort when needed!
	if (modrm_check32(&params,1,0)) return; //Abort when needed!
	oper1d = modrm_read32(&params,1);
	if (cpudebugger) //Debugger on?
	{
		modrm_debugger32(&params,0,1); //Get src!
		switch (MODRM_REG(params.modrm)) //What function?
		{
		case 0: //ROL
			debugger_setcommand("ROLD %s,1",&modrm_param2);
			break;
		case 1: //ROR
			debugger_setcommand("RORD %s,1",&modrm_param2);
			break;
		case 2: //RCL
			debugger_setcommand("RCLD %s,1",&modrm_param2);
			break;
		case 3: //RCR
			debugger_setcommand("RCRD %s,1",&modrm_param2);
			break;
		case 4: //SHL
		case 6: //--- Unknown Opcode! --- Undocumented opcode!
			debugger_setcommand("SHLD %s,1",&modrm_param2);
			break;
		case 5: //SHR
			debugger_setcommand("SHRD %s,1",&modrm_param2);
			break;
		case 7: //SAR
			debugger_setcommand("SARD %s,1",&modrm_param2);
			break;
		default:
			break;
		}
	}
	modrm_write32(&params,1,op_grp2_32(1,0));
}

void CPU80386_OPD3() //GRP2 Ev,CL
{
	thereg = MODRM_REG(params.modrm);
	if (modrm_check32(&params,1,1)) return; //Abort when needed!
	if (modrm_check32(&params,1,0)) return; //Abort when needed!
	oper1d = modrm_read32(&params,1);
	if (cpudebugger) //Debugger on?
	{
		modrm_debugger32(&params,0,1); //Get src!
		switch (MODRM_REG(params.modrm)) //What function?
		{
		case 0: //ROL
			debugger_setcommand("ROLD %s,CL",&modrm_param2);
			break;
		case 1: //ROR
			debugger_setcommand("RORD %s,CL",&modrm_param2);
			break;
		case 2: //RCL
			debugger_setcommand("RCLD %s,CL",&modrm_param2);
			break;
		case 3: //RCR
			debugger_setcommand("RCRD %s,CL",&modrm_param2);
			break;
		case 4: //SHL
			debugger_setcommand("SHLD %s,CL",&modrm_param2);
			break;
		case 5: //SHR
			debugger_setcommand("SHRD %s,CL",&modrm_param2);
			break;
		case 6: //--- Unknown Opcode! ---
			debugger_setcommand("<UNKNOWN MODR/M: GRP2(w) /6, CL>");
			break;
		case 7: //SAR
			debugger_setcommand("SARD %s,CL",&modrm_param2);
			break;
		default:
			break;
		}
	}
	modrm_write32(&params,1,op_grp2_32(REG_CL,1));
}

void CPU80386_OPF7() //GRP3b Ev
{
	thereg = MODRM_REG(params.modrm);
	if (modrm_check32(&params,1,1)) return; //Abort when needed!
	if ((thereg>1) && (thereg<4)) //NOT/NEG?
	{
		if (modrm_check32(&params,1,0)) return; //Abort when needed!
	}
	oper1d = modrm_read32(&params,1);
	if (cpudebugger) //Debugger on?
	{
		modrm_debugger32(&params,0,1); //Get src!
		switch (thereg) //What function?
		{
		case 0: //TEST modrm32, imm32
		case 1: //--- Undocumented opcode, same as above!
			debugger_setcommand("TESTD %s,%02x",&modrm_param2,immw);
			break;
		case 2: //NOT
			modrm_generateInstructionTEXT("NOTD",32,0,PARAM_MODRM2);
			break;
		case 3: //NEG
			modrm_generateInstructionTEXT("NEGD",32,0,PARAM_MODRM2);
			break;
		case 4: //MUL
			modrm_generateInstructionTEXT("MULD",32,0,PARAM_MODRM2);
			break;
		case 5: //IMUL
			modrm_generateInstructionTEXT("IMULD",32,0,PARAM_MODRM2);
			break;
		case 6: //DIV
			modrm_generateInstructionTEXT("DIVD",32,0,PARAM_MODRM2);
			break;
		case 7: //IDIV
			modrm_generateInstructionTEXT("IDIVD",32,0,PARAM_MODRM2);
			break;
		default:
			break;
		}
	}
	op_grp3_32();
	if ((thereg>1) && (thereg<4)) //NOT/NEG?
	{
		modrm_write32(&params,1,res32);
	}
}
//All OK up till here.

/*

DEBUG: REALLY SUPPOSED TO HANDLE HERE?

*/

void CPU80386_OPFF() //GRP5 Ev
{
	thereg = MODRM_REG(params.modrm);
	if (modrm_check32(&params,1,1)) return; //Abort when needed!
	oper1d = modrm_read32(&params,1);
	ea = modrm_offset32(&params,1);
	if (cpudebugger) //Debugger on?
	{
		modrm_debugger32(&params,0,1); //Get src!
		switch (MODRM_REG(params.modrm)) //What function?
		{
		case 0: //INC modrm8
			modrm_generateInstructionTEXT("INCD",32,0,PARAM_MODRM2); //INC!
			break;
		case 1: //DEC modrm8
			modrm_generateInstructionTEXT("DECD",32,0,PARAM_MODRM2); //DEC!
			break;
		case 2: //CALL
			modrm_generateInstructionTEXT("CALL",32,0,PARAM_MODRM2); //CALL!
			break;
		case 3: //CALL Mp (Read address word and jump there)
			modrm_generateInstructionTEXT("CALL",32,0,PARAM_MODRM2); //Jump to the address pointed here!
			//debugger_setcommand("CALL %04X:%04X",MMU_rw(CPU_SEGMENT_CS,REG_CS,ea,0),MMU_rw(CPU_SEGMENT_CS,REG_CS,ea+2,0)); //Based on CALL Ap
			break;
		case 4: //JMP
			modrm_generateInstructionTEXT("JMP",32,0,PARAM_MODRM2); //JMP to the register!
			break;
		case 5: //JMP Mp
			modrm_generateInstructionTEXT("JMP",32,0,PARAM_MODRM2); //Jump to the address pointed here!
			//debugger_setcommand("JMP %04X:%04X",MMU_rw(CPU_SEGMENT_CS,REG_CS,ea,0),MMU_rw(CPU_SEGMENT_CS,REG_CS,ea+2,0)); //JMP to destination!
			break;
		case 6: //PUSH
			modrm_generateInstructionTEXT("PUSHD",32,0,PARAM_MODRM2); //PUSH!
			break;
		case 7: //---
			debugger_setcommand("<UNKNOWN Opcode: GRP5(w) /7>");
			break;
		default:
			break;
		}
	}
	op_grp5_32();
}

/*

Special stuff for NO COprocessor (8087) present/available (default)!

*/

void unkOP_80386() //Unknown opcode on 8086?
{
	//dolog("8086","Unknown opcode on 8086: %02X",CPU[activeCPU].lastopcode); //Last read opcode!
	CPU_unkOP(); //Execute the unknown opcode exception handler, if any!
}

//Gecontroleerd: 100% OK!

//Now, the GRP opcodes!

OPTINLINE void op_grp2_cycles32(byte cnt, byte varshift)
{
	switch (varshift) //What type of shift are we using?
	{
	case 0: //Reg/Mem with 1 shift?
		if (MODRM_EA(params)) //Mem?
		{
			CPU[activeCPU].cycles_OP = 15 + MODRM_EA(params); //Mem
		}
		else //Reg?
		{
			CPU[activeCPU].cycles_OP = 2; //Reg
		}
		break;
	case 1: //Reg/Mem with variable shift?
		if (MODRM_EA(params)) //Mem?
		{
			CPU[activeCPU].cycles_OP = 20 + MODRM_EA(params) + (cnt << 2); //Mem
		}
		else //Reg?
		{
			CPU[activeCPU].cycles_OP = 8 + (cnt << 2); //Reg
		}
		break;
	case 2: //Reg/Mem with immediate variable shift(NEC V20/V30)?
		if (MODRM_EA(params)) //Mem?
		{
			CPU[activeCPU].cycles_OP = 20 + MODRM_EA(params) + (cnt << 2); //Mem
		}
		else //Reg?
		{
			CPU[activeCPU].cycles_OP = 8 + (cnt << 2); //Reg
		}
		break;
	}
}

uint_32 op_grp2_32(byte cnt, byte varshift) {
	//uint32_t d,
	INLINEREGISTER uint_32 s, shift, oldCF, msb;
	//if (cnt>0x10) return(oper1d); //NEC V20/V30+ limits shift count
	if (EMULATED_CPU >= CPU_NECV30) cnt &= 0x1F; //Clear the upper 3 bits to become a NEC V20/V30+!
	s = oper1d;
	oldCF = FLAG_CF;
	switch (thereg) {
	case 0: //ROL r/m32
		for (shift = 1; shift <= cnt; shift++) {
			if (s & 0x80000000) FLAGW_CF(1); else FLAGW_CF(0);
			s = s << 1;
			s = s | FLAG_CF;
		}
		if (cnt==1) FLAGW_OF(FLAG_CF ^ ((s >> 31) & 1));
		break;

	case 1: //ROR r/m32
		for (shift = 1; shift <= cnt; shift++) {
			FLAGW_CF(s & 1);
			s = (s >> 1) | (FLAG_CF << 31);
		}
		if (cnt==1) FLAGW_OF((s >> 31) ^ ((s >> 30) & 1));
		break;

	case 2: //RCL r/m32
		for (shift = 1; shift <= cnt; shift++) {
			oldCF = FLAG_CF;
			if (s & 0x80000000) FLAGW_CF(1); else FLAGW_CF(0);
			s = s << 1;
			s = s | oldCF;
			//oldCF = ((s&0x8000)>>15)&1; //Save FLAG_CF!
			//s = (s<<1)+FLAG_CF;
			//FLAG_CF = oldCF;
		}
		if (cnt==1) FLAGW_OF(FLAG_CF ^ ((s >> 31) & 1));
		break;

	case 3: //RCR r/m32
		if (cnt==1) FLAGW_OF(((s >> 31) & 1) ^ FLAG_CF);
		for (shift = 1; shift <= cnt; shift++) {
			oldCF = FLAG_CF;
			FLAGW_CF(s & 1);
			s = (s >> 1) | (oldCF << 31);
			//oldCF = s&1;
			//s = (s<<1)+(FLAG_CF<<32);
			//FLAG_CF = oldCF;
		}
		if (cnt==1) FLAGW_OF((s >> 31) ^ ((s >> 30) & 1));
		break;

	case 4: case 6: //SHL r/m32
		//FLAGW_AF(0);
		for (shift = 1; shift <= cnt; shift++) {
			if (s & 0x80000000) FLAGW_CF(1); else FLAGW_CF(0);
			s = (s << 1) & 0xFFFFFFFF;
			//FLAGW_AF(1); //Auxiliary carry?
		}
		if ((cnt==1) && (FLAG_CF == (s >> 31))) FLAGW_OF(0); else FLAGW_OF(1);
		flag_szp32(s); break;

	case 5: //SHR r/m32
		if (cnt==1) FLAGW_OF((s & 0x80000000) ? 1 : 0);
		//FLAGW_AF(0);
		for (shift = 1; shift <= cnt; shift++) {
			FLAGW_CF(s & 1);
			s = s >> 1;
			//FLAGW_AF(1); //Auxiliary carry?
		}
		flag_szp32(s); break;

	case 7: //SAR r/m32
		msb = s & 0x80000000; //Read the MSB!
		//FLAGW_AF(0);
		for (shift = 1; shift <= cnt; shift++) {
			FLAGW_CF(s & 1);
			s = (s >> 1) | msb;
			//FLAGW_AF(1); //Auxiliary carry?
		}
		byte tempSF;
		tempSF = FLAG_SF; //Save the SF!
		/*flag_szp32(s);*/
		//http://www.electronics.dit.ie/staff/tscarff/8086_instruction_set/8086_instruction_set.html#SAR says only C and O flags!
		if (!cnt) //Nothing done?
		{
			FLAGW_SF(tempSF); //We don't update when nothing's done!
		}
		else if (cnt==1) //Overflow is cleared on all 1-bit shifts!
		{
			flag_s32(s); //Affect sign as well!
			FLAGW_OF(0); //Cleared!
		}
		else if (cnt) //Anything shifted at all?
		{
			flag_s32(s); //Affect sign as well!
		}
		if ((EMULATED_CPU>=CPU_NECV30) && cnt) //NECV20+ affected?
		{
			flag_p32(s); //Affect parity as well!
			flag_s32(s); //Affect sign as well!
		}
		break;
	}
	op_grp2_cycles32(cnt, varshift|4);
	return(s & 0xFFFFFFFF);
}

byte tmps,tmpp; //Sign/parity backup!

extern byte CPU_databussize; //Current data bus size!

byte tempAL;
word tempAX;
uint_32 tempEAX;

OPTINLINE void op_div32(uint_64 valdiv, uint_32 divisor) {
	//word v1, v2;
	if (!divisor) { CPU_exDIV0(); return; }
	if ((valdiv / (uint_64)divisor) > 0xFFFFFFFF) { CPU_exDIV0(); return; }
	REG_EDX = (uint_32)((uint_64)valdiv % (uint_64)divisor);
	REG_EAX = (uint_32)(valdiv / (uint_64)divisor);
}

OPTINLINE void op_idiv32(uint_64 valdiv, uint_32 divisor) {
	//uint32_t v1, v2,

	if (!divisor) { CPU_exDIV0(); return; }
	/*
	uint_32 d1, d2, s1, s2;
	int sign;
	s1 = valdiv;
	s2 = divisor;
	s2 = (s2 & 0x8000) ? (s2 | 0xffff0000) : s2;
	sign = (((s1 ^ s2) & 0x80000000) != 0);
	s1 = (s1 < 0x80000000) ? s1 : ((~s1 + 1) & 0xffffffff);
	s2 = (s2 < 0x80000000) ? s2 : ((~s2 + 1) & 0xffffffff);
	d1 = s1 / s2;
	d2 = s1 % s2;
	if (d1 & 0xFFFF0000) { CPU_exDIV0(); return; }
	if (sign) {
	d1 = (~d1 + 1) & 0xffff;
	d2 = (~d2 + 1) & 0xffff;
	}
	REG_AX = d1;
	REG_DX = d2;
	*/

	//Same, but with normal instructions!
	union
	{
		uint_64 valdivw;
		int_64 valdivs;
	} dataw1, //For loading the signed value of the registers!
		dataw2; //For performing calculations!

	union
	{
		uint_32 divisorb;
		int_32 divisors;
	} datab1, datab2; //For converting the data to signed values!

	dataw1.valdivw = valdiv; //Load word!
	datab1.divisorb = divisor; //Load divisor!

	dataw2.valdivs = dataw1.valdivs; //Set and...
	dataw2.valdivs /= datab1.divisors; //... Divide!

	datab2.divisors = (int_32)dataw2.valdivs; //Try to load the signed result!
	if ((int_32)dataw2.valdivw != (int_32)datab2.divisors) { CPU_exDIV0(); return; } //Overflow (data loss)!

	REG_EAX = datab2.divisorb; //Divided!
	dataw2.valdivs = dataw1.valdivs; //Reload and...
	dataw2.valdivs %= datab1.divisors; //... Modulo!
	datab1.divisors = (int_32)dataw2.valdivs; //Convert to 8-bit!
	REG_EDX = datab1.divisorb; //Move rest into result!

							  //if (valdiv > 0x7FFFFFFF) v1 = valdiv - 0xFFFFFFFF - 1; else v1 = valdiv;
							  //if (divisor > 32767) v2 = divisor - 65536; else v2 = divisor;
							  //if ((v1/v2) > 65535) { CPU80386_INTERNAL_int(0); return; }
							  //temp3 = (v1/v2) & 65535;
							  //regs.wordregs[regax] = temp3;
							  //temp3 = (v1%v2) & 65535;
							  //regs.wordregs[regdx] = temp3;
}

void op_grp3_32() {
	//uint32_t d1, d2, s1, s2, sign;
	//word d, s;
	//oper1d = signext(oper1b); oper2d = signext(oper2b);
	//sprintf(msg, "  oper1d: %04X    oper2d: %04X\n", oper1d, oper2d); print(msg);
	switch (thereg) {
	case 0: case 1: //TEST
		CPU80386_internal_TEST32(oper1d, immw, 3);
		break;
	case 2: //NOT
		res32 = ~oper1d;
		if (MODRM_EA(params)) //Memory?
		{
			CPU[activeCPU].cycles_OP = 16 + MODRM_EA(params); //Mem!
		}
		else //Register?
		{
			CPU[activeCPU].cycles_OP = 3; //Reg!
		}
		break;
	case 3: //NEG
		res32 = (~oper1d) + 1;
		flag_sub32(0, oper1d);
		if (res32) FLAGW_CF(1); else FLAGW_CF(0);
		//FLAGW_AF((res32&0xF)?1:0); //Auxiliary flag!
		if (MODRM_EA(params)) //Memory?
		{
			CPU[activeCPU].cycles_OP = 16 + MODRM_EA(params); //Mem!
		}
		else //Register?
		{
			CPU[activeCPU].cycles_OP = 3; //Reg!
		}
		break;
	case 4: //MULW
		tempEAX = REG_EAX; //Save a backup for calculating cycles!
		temp1.val64 = (uint32_t)oper1d * (uint32_t)REG_AX;
		REG_EAX = temp1.val32;
		REG_EDX = temp1.val32high;
		if (REG_EDX) { FLAGW_CF(1); FLAGW_OF(1); }
		else { FLAGW_CF(0); FLAGW_OF(0); }
		//if ((EMULATED_CPU==CPU_8086) && temp1.val32) FLAGW_ZF(0); //8086/8088 clears the Zero flag when not zero only.
		if (MODRM_EA(params)) //Memory?
		{
			CPU[activeCPU].cycles_OP = 124 + MODRM_EA(params); //Mem max!
		}
		else //Register?
		{
			CPU[activeCPU].cycles_OP = 118; //Reg!
		}
		if (NumberOfSetBits(tempEAX)>1) //More than 1 bit set?
		{
			CPU[activeCPU].cycles_OP += NumberOfSetBits(tempEAX) - 1; //1 cycle for all bits more than 1 bit set!
		}
		break;
	case 5: //IMULW
		temp1.val32 = REG_EAX;
		temp2.val32 = oper1d;
		//Sign extend!
		if (temp1.val32 & 0x80000000) temp1.val64 |= 0xFFFFFFFF00000000ULL;
		if (temp2.val32 & 0x80000000) temp2.val64 |= 0xFFFFFFFF00000000ULL;
		temp3.val64s = temp1.val64s; //Load and...
		temp3.val64s *= temp2.val64s; //Signed multiplication!
		REG_EAX = temp3.val32; //into register ax
		REG_EDX = temp3.val32high; //into register dx
		FLAGW_OF(((int_32)temp3.val64s != temp3.val64s)?1:0); //Overflow occurred?
		FLAGW_CF(FLAG_OF); //Same!
		FLAGW_SF((REG_EDX>>31)&1); //Sign flag is affected!
		if (MODRM_EA(params)) //Memory?
		{
			CPU[activeCPU].cycles_OP = 128 + MODRM_EA(params); //Mem max!
		}
		else //Register?
		{
			CPU[activeCPU].cycles_OP = 134; //Reg max!
		}
		break;
	case 6: //DIV
		op_div32(((uint_64)REG_EDX << 32) | REG_EAX, oper1d);
		break;
	case 7: //IDIV
		op_idiv32(((uint_64)REG_EDX << 32) | REG_EAX, oper1d); break;
	}
}

void op_grp5_32() {
	MODRM_PTR info; //To contain the info!
	word destCS;
	switch (thereg) {
	case 0: //INC Ev
		if (modrm_check32(&params,1,1)) return; //Abort when needed!
		if (modrm_check32(&params,1,0)) return; //Abort when needed!
		CPU80386_internal_INC32(modrm_addr32(&params,1,0));
		break;
	case 1: //DEC Ev
		if (modrm_check32(&params,1,1)) return; //Abort when needed!
		if (modrm_check32(&params,1,0)) return; //Abort when needed!
		CPU80386_internal_DEC32(modrm_addr32(&params,1,0));
		break;
	case 2: //CALL Ev
		if (checkStackAccess(1,1,1)) return; //Abort when needed!
		CPU_PUSH32(&REG_EIP);
		CPU_JMPabs(oper1d);
		if (MODRM_EA(params)) //Mem?
		{
			CPU[activeCPU].cycles_OP = 21 + MODRM_EA(params); /* Intrasegment indirect through memory */
		}
		else //Register?
		{
			CPU[activeCPU].cycles_OP = 16; /* Intrasegment indirect through register */
		}
		CPU_flushPIQ(-1); //We're jumping to another address!
		break;
	case 3: //CALL Mp
		modrm_decode32(&params, &info, 1); //Get data!

		modrm_addoffset = 0; //First IP!
		if (modrm_check32(&params,1,1)) return; //Abort when needed!
		modrm_addoffset = 2; //Then destination CS!
		if (modrm_check16(&params,1,1)) return; //Abort when needed!

		modrm_addoffset = 0; //First IP!
		destEIP = modrm_read32(&params,1); //Get destination IP!
		CPUPROT1
		modrm_addoffset = 2; //Then destination CS!
		destCS = modrm_read16(&params,1); //Get destination CS!
		CPUPROT1
		modrm_addoffset = 0;
		CPU80386_CALLF(destCS,destEIP); //Call the destination address!
		CPUPROT1
		if (MODRM_EA(params)) //Mem?
		{
			CPU[activeCPU].cycles_OP = 37 + MODRM_EA(params); /* Intersegment indirect */
		}
		else //Register?
		{
			CPU[activeCPU].cycles_OP = 28; /* Intersegment direct */
		}
		CPUPROT2
		CPUPROT2
		CPUPROT2
		break;
	case 4: //JMP Ev
		CPU_JMPabs(oper1d);
		CPU_flushPIQ(-1); //We're jumping to another address!
		if (MODRM_EA(params)) //Memory?
		{
			CPU[activeCPU].cycles_OP = 18 + MODRM_EA(params); /* Intrasegment indirect through memory */
		}
		else //Register?
		{
			CPU[activeCPU].cycles_OP = 11; /* Intrasegment indirect through register */
		}
		break;
	case 5: //JMP Mp
		modrm_decode32(&params, &info, 1); //Get data!
		if (checkMMUaccess(get_segment_index(info.segmentregister), info.mem_segment, info.mem_offset,1,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) return; //Abort on fault!
		if (checkMMUaccess(get_segment_index(info.segmentregister), info.mem_segment, info.mem_offset+1,1,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) return; //Abort on fault!
		if (checkMMUaccess(get_segment_index(info.segmentregister), info.mem_segment, info.mem_offset+2,1,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) return; //Abort on fault!
		if (checkMMUaccess(get_segment_index(info.segmentregister), info.mem_segment, info.mem_offset+3,1,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) return; //Abort on fault!
		if (checkMMUaccess(get_segment_index(info.segmentregister), info.mem_segment, info.mem_offset+4,1,getCPL(),!CPU_Address_size[activeCPU],0|0x8)) return; //Abort on fault!
		if (checkMMUaccess(get_segment_index(info.segmentregister), info.mem_segment, info.mem_offset+5,1,getCPL(),!CPU_Address_size[activeCPU],1|0x8)) return; //Abort on fault!

		destEIP = MMU_rdw(get_segment_index(info.segmentregister), info.mem_segment, info.mem_offset, 0,!CPU_Address_size[activeCPU]);
		CPUPROT1
		destCS = MMU_rw(get_segment_index(info.segmentregister), info.mem_segment, info.mem_offset + 4, 0,!CPU_Address_size[activeCPU]);
		CPUPROT1
		segmentWritten(CPU_SEGMENT_CS, destCS, 1);
		CPU_flushPIQ(-1); //We're jumping to another address!
		CPUPROT1
		if (MODRM_EA(params)) //Memory?
		{
			CPU[activeCPU].cycles_OP = 24 + MODRM_EA(params); /* Intersegment indirect through memory */
		}
		else //Register?
		{
			CPU[activeCPU].cycles_OP = 11; /* Intersegment indirect through register */
		}
		CPUPROT2
		CPUPROT2
		CPUPROT2
		break;
	case 6: //PUSH Ev
		if (checkStackAccess(1,1,1)) return; //Abort on fault!
		CPU_PUSH32(&oper1d); break;
		CPUPROT1
		if (MODRM_EA(params)) //Memory?
		{
			CPU[activeCPU].cycles_OP = 16+MODRM_EA(params); /*Push Mem!*/
		}
		else //Register?
		{
			CPU[activeCPU].cycles_OP = 11; /*Push Reg!*/
		}
		CPUPROT2
		break;
	default: //Unknown OPcode?
		CPU_unkOP(); //Execute the unknown opcode exception handler, if any!
		break;
	}
}

/*

80186 32-bit extensions

*/

void CPU386_OP60()
{
	debugger_setcommand("PUSHA");
	if (checkStackAccess(8,1,1)) return; //Abort on fault!
	uint_32 oldESP = REG_ESP;    //PUSHA
	CPU_PUSH32(&REG_EAX);
	CPUPROT1
	CPU_PUSH32(&REG_ECX);
	CPUPROT1
	CPU_PUSH32(&REG_EDX);
	CPUPROT1
	CPU_PUSH32(&REG_EBX);
	CPUPROT1
	CPU_PUSH32(&oldESP);
	CPUPROT1
	CPU_PUSH32(&REG_EBP);
	CPUPROT1
	CPU_PUSH32(&REG_ESI);
	CPUPROT1
	CPU_PUSH32(&REG_EDI);
	CPUPROT2
	CPUPROT2
	CPUPROT2
	CPUPROT2
	CPUPROT2
	CPUPROT2
	CPUPROT2
}

void CPU386_OP61()
{
	debugger_setcommand("POPA");
	if (checkStackAccess(8,0,1)) return; //Abort on fault!
	REG_EDI = CPU_POP32();
	CPUPROT1
	REG_ESI = CPU_POP32();
	CPUPROT1
	REG_EBP = CPU_POP32();
	CPUPROT1
	CPU_POP32();
	CPUPROT1
	REG_EBX = CPU_POP32();
	CPUPROT1
	REG_EDX = CPU_POP32();
	CPUPROT1
	REG_ECX = CPU_POP32();
	CPUPROT1
	REG_EAX = CPU_POP32();
	CPUPROT2
	CPUPROT2
	CPUPROT2
	CPUPROT2
	CPUPROT2
	CPUPROT2
	CPUPROT2
}

extern byte modrm_addoffset; //Add this offset to ModR/M reads!

//62 not implemented in fake86? Does this not exist?
void CPU386_OP62()
{
	modrm_debugger32(&params,0,1); //Debug the location!
	debugger_setcommand("BOUND %s,%s",modrm_param1,modrm_param2); //Opcode!

	if (modrm_isregister(params)) //ModR/M may only be referencing memory?
	{
		unkOP_186(); //Raise #UD!
		return; //Abort!
	}

	uint_32 bound_min, bound_max;
	uint_32 theval;
	modrm_addoffset = 0; //No offset!
	if (modrm_check32(&params,0,1)) return; //Abort on fault!
	if (modrm_check32(&params,1,1)) return; //Abort on fault!
	modrm_addoffset = 4; //Max offset!
	if (modrm_check32(&params,1,1)) return; //Abort on fault!

	modrm_addoffset = 0; //No offset!
	theval = modrm_read32(&params,0); //Read index!
	bound_min=modrm_read32(&params,1); //Read min!
	modrm_addoffset = 4; //Max offset!
	bound_max=modrm_read32(&params,1); //Read max!
	modrm_addoffset = 0; //Reset offset!
	if ((unsigned2signed32(theval)<unsigned2signed32(bound_min)) || (unsigned2signed32(theval)>unsigned2signed32(bound_max)))
	{
		//BOUND Gv,Ma
		CPU_BoundException(); //Execute bound exception!
	}
}

void CPU386_OP68()
{
	uint_32 val = imm32;    //PUSH Iz
	debugger_setcommand("PUSH %08X",val);
	if (checkStackAccess(1,1,1)) return; //Abort on fault!
	CPU_PUSH32(&val);
}

extern MODRM_PTR info, info2; //For storing ModR/M Info(second for 186+ IMUL instructions)!

void CPU386_OP69()
{
	modrm_decode32(&params,&info,0); //Reg!
	modrm_decode32(&params,&info2,1); //Second parameter(R/M)!
	if (MODRM_MOD(params.modrm)==3) //Two-operand version?
	{
		debugger_setcommand("IMULD %s,%04X",info.text,immw); //IMUL reg,imm16
	}
	else //Three-operand version?
	{
		debugger_setcommand("IMULD %s,%s,%04X",info.text,info2.text,immw); //IMUL reg,r/m16,imm16
	}
	if (MODRM_MOD(params.modrm)!=3) //Use R/M to calculate the result(Three-operand version)?
	{
		if (modrm_check32(&params,1,1)) return; //Abort on fault!
		temp1.val64 = (uint_64)modrm_read32(&params,1); //Read R/M!
	}
	else
	{
		temp1.val64 = (uint_64)modrm_read32(&params,0); //Read reg instead! Word register = Word register * imm16!
	}
	temp2.val64 = (uint_64)imm32; //Immediate word is second/third parameter!
	if ((temp1.val64 &0x80000000ULL)==0x80000000ULL) temp1.val64 |= 0xFFFFFFFF00000000ULL;
	if ((temp2.val64 &0x80000000ULL)==0x80000000ULL) temp2.val64 |= 0xFFFFFFFF00000000ULL;
	temp3.val64s = temp1.val32s; //Load and...
	temp3.val64s *= temp2.val32s; //Signed multiplication!
	modrm_write32(&params,0,temp3.val32); //Write to the destination(register)!
	if (((temp3.val64>>31)==0ULL) || ((temp3.val64>>31)==0x1FFFFFFFFULL)) FLAGW_OF(0); //Overflow flag is cleared when high word is a sign extension of the low word!
	else FLAGW_OF(1);
	FLAGW_CF(FLAG_OF); //OF=CF!
	FLAGW_SF(((uint_64)temp3.val32&0x80000000U)>>31); //Sign!
	FLAGW_PF(parity[temp3.val32&0xFF]); //Parity flag!
	FLAGW_ZF((temp3.val32==0)?1:0); //Set the zero flag!
}

void CPU386_OP6B()
{
	modrm_decode32(&params,&info,0); //Store the address!
	modrm_decode32(&params,&info2,1); //Store the address(R/M)!
	if (MODRM_MOD(params.modrm)==3) //Two-operand version?
	{
		debugger_setcommand("IMULD %s,%02X",info.text,immb); //IMUL reg,imm8
	}
	else //Three-operand version?
	{
		debugger_setcommand("IMULD %s,%s,%02X",info.text,info2.text,immb); //IMUL reg,r/m16,imm8
	}
	if (MODRM_MOD(params.modrm)!=3) //Use R/M to calculate the result(Three-operand version)?
	{
		if (modrm_check32(&params,1,1)) return; //Abort on fault!
		temp1.val64 = (uint_64)modrm_read32(&params,1); //Read R/M!
	}
	else
	{
		temp1.val64 = (uint_64)modrm_read32(&params,0); //Read reg instead! Word register = Word register * imm8 sign extended!
	}
	temp2.val64 = (uint_64)immb; //Read unsigned parameter!

	if (temp1.val64&0x80000000ULL) temp1.val64 |= 0xFFFFFFFF00000000ULL;//Sign extend to 32 bits!
	if (temp2.val64&0x80ULL) temp2.val64 |= 0xFFFFFFFFFFFFFF00ULL; //Sign extend to 32 bits!
	temp3.val64s = temp1.val64s * temp2.val64s;
	modrm_write32(&params,0,temp3.val32); //Write to register!
	if (((temp3.val64>>31)==0ULL) || ((temp3.val64>>31)==0x1FFFFFFFFULL)) FLAGW_OF(0); //Overflow flag is cleared when high word is a sign extension of the low word!
	else FLAGW_OF(1);
	FLAGW_CF(FLAG_OF); //Same!
	FLAGW_SF((temp3.val32&0x80000000)>>31); //Sign!
	FLAGW_PF(parity[temp3.val32&0xFF]); //Parity flag!
	FLAGW_ZF((temp3.val32==0)?1:0); //Set the zero flag!
}

void CPU386_OP6D()
{
	debugger_setcommand("INSD");
	if (blockREP) return; //Disabled REP!
	uint_32 data;
	if (checkMMUaccess(get_segment_index(CPU_segment_ptr(CPU_SEGMENT_ES)),CPU_segment(CPU_SEGMENT_ES),(CPU_Address_size[activeCPU]?REG_EDI:REG_DI),0,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) return; //Abort on fault!
	if (checkMMUaccess(get_segment_index(CPU_segment_ptr(CPU_SEGMENT_ES)),CPU_segment(CPU_SEGMENT_ES),(CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+1,0,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) return; //Abort on fault!
	if (checkMMUaccess(get_segment_index(CPU_segment_ptr(CPU_SEGMENT_ES)),CPU_segment(CPU_SEGMENT_ES),(CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+2,0,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) return; //Abort on fault!
	if (checkMMUaccess(get_segment_index(CPU_segment_ptr(CPU_SEGMENT_ES)),CPU_segment(CPU_SEGMENT_ES),(CPU_Address_size[activeCPU]?REG_EDI:REG_DI)+3,0,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) return; //Abort on fault!
	if (CPU_PORT_IN_D(0,REG_DX, &data)) return; //Read the port!
	CPUPROT1
	MMU_wdw(get_segment_index(CPU_segment_ptr(CPU_SEGMENT_ES)),CPU_segment(CPU_SEGMENT_ES),(CPU_Address_size[activeCPU]?REG_EDI:REG_DI),data,!CPU_Address_size[activeCPU]);    //INSW
	CPUPROT1
	if (FLAG_DF)
	{
		if (CPU_Address_size[activeCPU])		
		{
			REG_EDI -= 4;
		}
		else
		{
			REG_DI -= 4;
		}
	}
	else
	{
		if (CPU_Address_size[activeCPU])		
		{
			REG_EDI += 4;
		}
		else
		{
			REG_DI += 4;
		}
	}
	CPUPROT2
	CPUPROT2
}

void CPU386_OP6F()
{
	debugger_setcommand("OUTSD");
	if (blockREP) return; //Disabled REP!
	uint_32 data;
	if (checkMMUaccess(get_segment_index(CPU_segment_ptr(CPU_SEGMENT_DS)),CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size[activeCPU]?REG_ESI:REG_SI),1,getCPL(),!CPU_Address_size[activeCPU],0|0x10)) return; //Abort on fault!
	if (checkMMUaccess(get_segment_index(CPU_segment_ptr(CPU_SEGMENT_DS)),CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size[activeCPU]?REG_ESI:REG_SI)+1,1,getCPL(),!CPU_Address_size[activeCPU],1|0x10)) return; //Abort on fault!
	if (checkMMUaccess(get_segment_index(CPU_segment_ptr(CPU_SEGMENT_DS)),CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size[activeCPU]?REG_ESI:REG_SI)+2,1,getCPL(),!CPU_Address_size[activeCPU],2|0x10)) return; //Abort on fault!
	if (checkMMUaccess(get_segment_index(CPU_segment_ptr(CPU_SEGMENT_DS)),CPU_segment(CPU_SEGMENT_DS),(CPU_Address_size[activeCPU]?REG_ESI:REG_SI)+3,1,getCPL(),!CPU_Address_size[activeCPU],3|0x10)) return; //Abort on fault!
	data = MMU_rdw(get_segment_index(CPU_segment_ptr(CPU_SEGMENT_DS)), CPU_segment(CPU_SEGMENT_DS), (CPU_Address_size[activeCPU]?REG_ESI:REG_SI), 0,!CPU_Address_size[activeCPU]);
	CPUPROT1
	if (CPU_PORT_OUT_D(0,REG_DX,data)) return;    //OUTS DX,Xz
	CPUPROT1
	if (FLAG_DF)
	{
		if (CPU_Address_size[activeCPU])		
		{
			REG_ESI -= 2;
		}
		else
		{
			REG_SI -= 2;
		}
	}
	else
	{
		if (CPU_Address_size[activeCPU])		
		{
			REG_ESI += 2;
		}
		else
		{
			REG_SI += 2;
		}
	}
	CPUPROT2
	CPUPROT2
}

void CPU386_OPC1()
{
	oper2d = (word)immb;
	thereg = MODRM_REG(params.modrm);

	modrm_decode32(&params,&info,1); //Store the address for debugging!
	switch (thereg) //What function?
	{
		case 0: //ROL
			debugger_setcommand("ROLD %s,%02X",info.text,oper2d);
			break;
		case 1: //ROR
			debugger_setcommand("RORD %s,%02X",info.text,oper2d);
			break;
		case 2: //RCL
			debugger_setcommand("RCLD %s,%02X",info.text,oper2d);
			break;
		case 3: //RCR
			debugger_setcommand("RCRD %s,%02X",info.text,oper2d);
			break;
		case 4: //SHL
			debugger_setcommand("SHLD %s,%02X",info.text,oper2d);
			break;
		case 5: //SHR
			debugger_setcommand("SHRD %s,%02X",info.text,oper2d);
			break;
		case 6: //--- Unknown Opcode! --- Undocumented opcode!
			debugger_setcommand("SHLD %s,%02X",info.text,oper2d);
			break;
		case 7: //SAR
			debugger_setcommand("SARD %s,%02X",info.text,oper2d);
			break;
		default:
			break;
	}
	
	if (modrm_check32(&params,1,1)) return; //Abort on error!
	if (modrm_check32(&params,1,0)) return; //Abort on error!
	oper1d = modrm_read32(&params,1);

	modrm_write32(&params,1,op_grp2_32((byte)oper2d,2));
} //GRP2 Ev,Ib

extern byte ENTER_L; //Level value of the ENTER instruction!
void CPU386_OPC8()
{
	uint_32 temp16;    //ENTER Iw,Ib
	word stacksize = immw;
	byte nestlev = immb;
	uint_32 bpdata;
	debugger_setcommand("ENTER %04X,%02X",stacksize,nestlev);
	nestlev &= 0x1F; //MOD 32!
	if (EMULATED_CPU>CPU_80486) //We don't check it all before, but during the execution on 486- processors!
	{
		if (checkStackAccess(1+nestlev,1,1)) return; //Abort on error!
		if (checkENTERStackAccess((nestlev>1)?(nestlev-1):0,1)) return; //Abort on error!
	}
	ENTER_L = nestlev; //Set the nesting level used!
	//according to http://www.felixcloutier.com/x86/ENTER.html
	if (EMULATED_CPU<=CPU_80486) //We don't check it all before, but during the execution on 486- processors!
	{
		if (checkStackAccess(1,1,1)) return; //Abort on error!		
	}

	/*
	CPU[activeCPU].have_oldESP = 1; //We have an old ESP to jump back to!
	CPU[activeCPU].oldESP = REG_ESP; //Back-up!
	*/ //Done automatically at the start of an instruction!

	CPU_PUSH32(&REG_EBP);
	uint_32 frametemp = REG_ESP;
	if (nestlev)
	{
		for (temp16=1; temp16<nestlev; ++temp16)
		{
			if (EMULATED_CPU<=CPU_80486) //We don't check it all before, but during the execution on 486- processors!
			{
				if (checkENTERStackAccess(1,1)) return; //Abort on error!				
			}
			bpdata = MMU_rdw(CPU_SEGMENT_SS,REG_SS,REG_EBP-(temp16<<2),0,1); //Read the value to copy.
			if (EMULATED_CPU<=CPU_80486) //We don't check it all before, but during the execution on 486- processors!
			{
				if (checkStackAccess(1,1,1)) return; //Abort on error!
			}
			CPU_PUSH32(&bpdata);
		}
		if (EMULATED_CPU<=CPU_80486) //We don't check it all before, but during the execution on 486- processors!
		{
			if (checkStackAccess(1,1,1)) return; //Abort on error!		
		}
		CPU_PUSH32(&frametemp); //Felixcloutier.com says frametemp, fake86 says Sp(incorrect).
	}
	
	REG_EBP = frametemp;
	REG_ESP -= stacksize; //Substract: the stack size is data after the buffer created, not immediately at the params.  
}
void CPU386_OPC9()
{
	debugger_setcommand("LEAVE");
	if (checkStackAccess(1,0,1)) return; //Abort on fault!
	REG_ESP = REG_EBP;    //LEAVE
	REG_EBP = CPU_POP32();
}

/*

80286 32-bit extensions aren't needed: they're 0F opcodes and 16-bit instructions only.

*/

/*

No 80386 are needed: only 0F opcodes are used(286+ 32-bit versions and 80386+ opcodes)!

*/
