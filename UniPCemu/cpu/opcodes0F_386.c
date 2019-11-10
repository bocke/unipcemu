/*

Copyright (C) 2019  Superfury

This file is part of UniPCemu.

UniPCemu is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

UniPCemu is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with UniPCemu.  If not, see <https://www.gnu.org/licenses/>.
*/

/* Same as opcodes, but the 0F extension! */

#include "headers/types.h" //Basic types
#include "headers/cpu/cpu.h" //CPU needed!
#include "headers/cpu/mmu.h" //MMU needed!
#include "headers/cpu/easyregs.h" //Easy register compatibility!
#include "headers/cpu/modrm.h" //MODR/M compatibility!
#include "headers/support/signedness.h" //CPU support functions!
#include "headers/emu/debugger/debugger.h" //Debugger support!
#include "headers/cpu/flags.h" //Flag support!
#include "headers/cpu/cpu_OP8086.h" //8086 support!
#include "headers/cpu/cpu_OP80286.h" //80286 support!
#include "headers/cpu/cpu_OP80386.h" //80386 support!
#include "headers/cpu/protection.h" //Protection support!
#include "headers/cpu/protecteddebugging.h" //Protected mode debugger support for LOADALL!
#include "headers/cpu/biu.h" //PIQ flushing support!
#include "headers/cpu/cpu_stack.h" //Stack support!
#include "headers/cpu/cpu_pmtimings.h" //Timings support!
#include "headers/cpu/easyregs.h" //Easy register support!

//Opcodes based on: http://www.logix.cz/michal/doc/i386/chp17-a3.htm#17-03-A

extern VAL64Splitter temp1, temp2, temp3, temp4, temp5; //All temporary values!

/*

First, 32-bit 80386 variants of the 80286 opcodes!

*/

//Reading of the 16-bit entries within descriptors!
#ifdef SDL_SwapLE16
#define DESC_16BITS(x) SDL_SwapLE16(x)
#define DESC_32BITS(x) SDL_SwapLE32(x)
#else
//Unsupported? Placeholder!
#define DESC_16BITS(x) (x)
#define DESC_32BITS(x) (x)
#endif

extern BIOS_Settings_TYPE BIOS_Settings; //BIOS Settings!
extern MODRM_PARAMS params;    //For getting all params!
extern MODRM_PTR info; //For storing ModR/M Info!
extern word oper1, oper2; //Buffers!
extern uint_32 oper1d, oper2d; //Buffers!
extern byte immb;
extern word immw;
extern uint_32 imm32;
extern byte thereg; //For function number!
extern int_32 modrm_addoffset; //Add this offset to ModR/M reads!

//Modr/m support, used when reg=NULL and custommem==0
extern byte MODRM_src0; //What destination operand in our modr/m? (1/2)
extern byte MODRM_src1; //What source operand in our modr/m? (2/2)

/*

Interrupts:
0x00: //Divide error (0x00)
0x01: //Debug Exceptions (0x01)
0x02: //NMI Interrupt
0x03: //Breakpoint: software only!
0x04: //INTO Detected Overflow
0x05: //BOUND Range Exceeded
0x06: //Invalid Opcode
0x07: //Coprocessor Not Available
0x08: //Double Fault
0x09: //Coprocessor Segment Overrun
0x0A: //Invalid Task State Segment
0x0B: //Segment not present
0x0C: //Stack fault
0x0D: //General Protection Fault
0x0E: //Page Fault
0x0F: //Reserved
//0x10:
0x10: //Coprocessor Error
0x11: //Allignment Check

*/

extern Handler CurrentCPU_opcode0F_jmptbl[512]; //Our standard internal standard opcode jmptbl!

extern char modrm_param1[256]; //Contains param/reg1
extern char modrm_param2[256]; //Contains param/reg2
extern byte cpudebugger; //CPU debugger active?
extern byte custommem; //Custom memory address?

//0F opcodes for 286+ processors!

//Based on http://ref.x86asm.net/coder32.html

void CPU386_OP0F00() //Various extended 286+ instructions GRP opcode.
{
	memcpy(&info,&params.info[MODRM_src0],sizeof(info)); //Store the address for debugging!
	switch (thereg) //What function?
	{
	case 0: //SLDT
		if ((CPU_Operand_size[activeCPU]==0) || (modrm_ismemory(params))) //Force 16-bit?
		{
			CPU286_OP0F00(); //Same as 80286!
			return;
		}
		if (getcpumode() != CPU_MODE_PROTECTED)
		{
			unkOP0F_286(); //We're not recognized in real mode!
			return;
		}
		debugger_setcommand("SLDT %s", info.text);
		if (unlikely(CPU[activeCPU].modrmstep == 0)) { if (modrm_check32(&params, MODRM_src0, 0|0x40)) return; if (modrm_check32(&params, MODRM_src0, 0|0xA0)) return; } //Abort on fault!
		if (CPU80386_instructionstepwritemodrmdw(0,(uint_32)REG_LDTR,MODRM_src0)) return; //Try and write it to the address specified!
		CPU_apply286cycles(); //Apply the 80286+ cycles!
		break;
	case 1: //STR
		if ((CPU_Operand_size[activeCPU]==0) || (modrm_ismemory(params))) //Force 16-bit?
		{
			CPU286_OP0F00(); //Same as 80286!
			return;
		}
		if (getcpumode() != CPU_MODE_PROTECTED)
		{
			unkOP0F_286(); //We're not recognized in real mode!
			return;
		}
		debugger_setcommand("STR %s", info.text);
		if (unlikely(CPU[activeCPU].modrmstep == 0)) { if (modrm_check32(&params, MODRM_src0, 0|0x40)) return; if (modrm_check32(&params, MODRM_src0, 0|0xA0)) return; } //Abort on fault!
		if (CPU80386_instructionstepwritemodrmdw(0,(uint_32)REG_TR,MODRM_src0)) return; //Try and write it to the address specified!
		CPU_apply286cycles(); //Apply the 80286+ cycles!
		break;
	default:
		CPU286_OP0F00(); //Same as 80286!
		break;
	}
}

void CPU386_OP0F01() //Various extended 286+ instruction GRP opcode.
{
	memcpy(&info,&params.info[MODRM_src0],sizeof(info)); //Store the address for debugging!
	switch (thereg) //What function?
	{
	case 0: //SGDT
		if (CPU_Operand_size[activeCPU] == 0) //16-bit?
		{
			CPU286_OP0F01(); //Same as 80286!
			return;
		}
		debugger_setcommand("SGDT %s", info.text);
		if (params.info[MODRM_src0].isreg==1) //We're storing to a register? Invalid!
		{
			unkOP0F_386();
			return; //Abort!
		}
		if (unlikely(CPU[activeCPU].modrmstep==0))
		{
			modrm_addoffset = 0;
			if (modrm_check16(&params,MODRM_src0,0|0x40)) return; //Abort on fault!
			modrm_addoffset = 2;
			if (modrm_check32(&params,MODRM_src0,0|0x40)) return; //Abort on fault!
			modrm_addoffset = 0;
			if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; //Abort on fault!
			modrm_addoffset = 2;
			if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; //Abort on fault!
		}

		modrm_addoffset = 0; //Add no bytes to the offset!
		if (CPU8086_instructionstepwritemodrmw(0,CPU[activeCPU].registers->GDTR.limit,MODRM_src0,0)) return; //Try and write it to the address specified!
		CPUPROT1
			modrm_addoffset = 2; //Add 2 bytes to the offset!
			if (CPU80386_instructionstepwritemodrmdw(2,CPU[activeCPU].registers->GDTR.base,MODRM_src0)) return; //Only 24-bits of limit, high byte is cleared with 386+, set with 286!
			CPU_apply286cycles(); //Apply the 80286+ cycles!
		CPUPROT2
		modrm_addoffset = 0; //Add no bytes to the offset!
		break;
	case 1: //SIDT
		if (CPU_Operand_size[activeCPU] == 0) //16-bit?
		{
			CPU286_OP0F01(); //Same as 80286!
			return;
		}
		debugger_setcommand("SIDT %s", info.text);
		if (params.info[MODRM_src0].isreg==1) //We're storing to a register? Invalid!
		{
			unkOP0F_386();
			return; //Abort!
		}

		if (unlikely(CPU[activeCPU].modrmstep==0))
		{
			modrm_addoffset = 0;
			if (modrm_check16(&params,MODRM_src0,0|0x40)) return; //Abort on fault!
			modrm_addoffset = 2;
			if (modrm_check32(&params,MODRM_src0,0|0x40)) return; //Abort on fault!
			modrm_addoffset = 0;
			if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; //Abort on fault!
			modrm_addoffset = 2;
			if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; //Abort on fault!
		}

		modrm_addoffset = 0; //Add no bytes to the offset!
		if (CPU8086_instructionstepwritemodrmw(0,CPU[activeCPU].registers->IDTR.limit,MODRM_src0,0)) return; //Try and write it to the address specified!
		CPUPROT1
			modrm_addoffset = 2; //Add 2 bytes to the offset!
			if (CPU80386_instructionstepwritemodrmdw(2,(CPU[activeCPU].registers->IDTR.base & 0xFFFFFFFF),MODRM_src0)) return; //Only 24-bits of limit, high byte is cleared with 386+, set with 286!
			CPUPROT1
				CPU_apply286cycles(); //Apply the 80286+ cycles!
			CPUPROT2
		CPUPROT2
		modrm_addoffset = 0; //Add no bytes to the offset!
		break;
	case 2: //LGDT
		if (CPU_Operand_size[activeCPU]==0) //16-bit version?
		{
			CPU286_OP0F01(); //Redirect 16-bits!
			return;
		}
		debugger_setcommand("LGDT %s", info.text);
		if (params.info[MODRM_src0].isreg==1) //We're storing to a register? Invalid!
		{
			unkOP0F_286();
			return; //Abort!
		}
		if ((getCPL() && (getcpumode() != CPU_MODE_REAL)) || (getcpumode()==CPU_MODE_8086)) //Privilege level isn't 0 or invalid in V86-mode?
		{
			THROWDESCGP(0,0,0); //Throw #GP!
			return; //Abort!
		}

		if (unlikely(CPU[activeCPU].modrmstep==0))
		{
			modrm_addoffset = 0;
			if (modrm_check16(&params,MODRM_src0,1|0x40)) return; //Abort on fault!
			modrm_addoffset = 2;
			if (modrm_check32(&params,MODRM_src0,1|0x40)) return; //Abort on fault!
			modrm_addoffset = 0;
			if (modrm_check16(&params,MODRM_src0,1|0xA0)) return; //Abort on fault!
			modrm_addoffset = 2;
			if (modrm_check32(&params,MODRM_src0,1|0xA0)) return; //Abort on fault!
		}

		modrm_addoffset = 0; //Add no bytes to the offset!
		if (CPU8086_instructionstepreadmodrmw(0,&oper1,MODRM_src0)) return; //Read the limit first!
		CPUPROT1
			modrm_addoffset = 2; //Add 2 bytes to the offset!
			if (CPU80386_instructionstepreadmodrmdw(2,&oper1d,MODRM_src0)) return; //Read the limit first!
			CPUPROT1
				CPU[activeCPU].registers->GDTR.base = oper1d; //Load the base!
				CPU[activeCPU].registers->GDTR.limit = oper1; //Load the limit!
				CPU_apply286cycles(); //Apply the 80286+ cycles!
			CPUPROT2
		CPUPROT2
		modrm_addoffset = 0; //Add no bytes to the offset!
		break;
	case 3: //LIDT
		if (CPU_Operand_size[activeCPU] == 0) //16-bit version?
		{
			CPU286_OP0F01(); //Redirect 16-bits!
			return;
		}
		debugger_setcommand("LIDT %s", info.text);
		if (params.info[MODRM_src0].isreg==1) //We're storing to a register? Invalid!
		{
			unkOP0F_286();
			return; //Abort!
		}
		if ((getCPL() && (getcpumode() != CPU_MODE_REAL)) || (getcpumode()==CPU_MODE_8086)) //Privilege level isn't 0 or invalid in V86-mode?
		{
			THROWDESCGP(0,0,0); //Throw #GP!
			return; //Abort!
		}

		if (unlikely(CPU[activeCPU].modrmstep==0))
		{
			modrm_addoffset = 0;
			if (modrm_check16(&params,MODRM_src0,1|0x40)) return; //Abort on fault!
			modrm_addoffset = 2;
			if (modrm_check32(&params,MODRM_src0,1|0x40)) return; //Abort on fault!
			modrm_addoffset = 0;
			if (modrm_check16(&params,MODRM_src0,1|0xA0)) return; //Abort on fault!
			modrm_addoffset = 2;
			if (modrm_check32(&params,MODRM_src0,1|0xA0)) return; //Abort on fault!
		}

		modrm_addoffset = 0; //Add no bytes to the offset!
		if (CPU8086_instructionstepreadmodrmw(0,&oper1,MODRM_src0)) return; //Read the limit first!
		CPUPROT1
			modrm_addoffset = 2; //Add 2 bytes to the offset!
			if (CPU80386_instructionstepreadmodrmdw(2,&oper1d,MODRM_src0)) return; //Read the limit first!
			CPUPROT1
				CPU[activeCPU].registers->IDTR.base = oper1d; //Load the base!
				CPU[activeCPU].registers->IDTR.limit = oper1; //Load the limit!
				CPU_apply286cycles(); //Apply the 80286+ cycles!
			CPUPROT2
		CPUPROT2
		modrm_addoffset = 0; //Add no bytes to the offset!
		break;
	case 4: //SMSW
		if ((CPU_Operand_size[activeCPU]==0) || (modrm_ismemory(params))) //Force 16-bit?
		{
			CPU286_OP0F01(); //Same as 80286!
			return;
		}
		debugger_setcommand("SMSW %s", info.text);
		if (unlikely(CPU[activeCPU].modrmstep == 0)) { if (modrm_check32(&params, MODRM_src0, 0|0x40)) return; if (modrm_check32(&params, MODRM_src0, 0|0xA0)) return; } //Abort on fault!
		if (CPU80386_instructionstepwritemodrmdw(0,CPU[activeCPU].registers->CR0,MODRM_src0)) return; //Store the MSW into the specified location!
		CPU_apply286cycles(); //Apply the 80286+ cycles!
		break;
	case 6: //LMSW
		CPU286_OP0F01(); //Same as 80286!
		break;
	case 5: //--- Unknown Opcode!
	case 7: //--- Unknown Opcode!
		unkOP0F_386(); //Unknown opcode!
		break;
	default:
		break;
	}
}

void CPU386_OP0F02() //LAR /r
{
	byte isconforming = 1;
	SEGMENT_DESCRIPTOR verdescriptor;
	sbyte loadresult;
	if (getcpumode() != CPU_MODE_PROTECTED)
	{
		unkOP0F_286(); //We're not recognized in real mode!
		return;
	}
	modrm_generateInstructionTEXT("LAR", 32, 0, PARAM_MODRM_01); //Our instruction text!
	if (unlikely(CPU[activeCPU].modrmstep == 0)) { if (modrm_check32(&params, MODRM_src1, 1|0x40)) return; if (modrm_check32(&params, MODRM_src1, 1|0xA0)) return; } //Abort on fault!
	if (CPU80386_instructionstepreadmodrmdw(0,&oper1d,MODRM_src1)) return; //Read the segment to check!
	CPUPROT1
		if ((loadresult = LOADDESCRIPTOR(-1, oper1d, &verdescriptor,0))==1) //Load the descriptor!
		{
			/*
			if ((loadresult = touchSegment(-1, oper1d, &verdescriptor, 0)) != 1) //Errored out during touching?
			{
				goto failedlar386;
			}
			*/
			if ((oper1d & 0xFFFC) == 0) //NULL segment selector?
			{
				goto invalidresultLAR386;
			}
			switch (GENERALSEGMENT_TYPE(verdescriptor))
			{
			case AVL_SYSTEM_RESERVED_0: //Invalid type?
			case AVL_SYSTEM_INTERRUPTGATE16BIT:
			case AVL_SYSTEM_TRAPGATE16BIT:
			case AVL_SYSTEM_RESERVED_1:
			case AVL_SYSTEM_RESERVED_2:
			case AVL_SYSTEM_RESERVED_3:
			case AVL_SYSTEM_INTERRUPTGATE32BIT:
			case AVL_SYSTEM_TRAPGATE32BIT:
				if (GENERALSEGMENT_S(verdescriptor) == 0) //System?
				{
					FLAGW_ZF(0); //Invalid descriptor type!
					break;
				}
			default: //Valid type?
				if (GENERALSEGMENT_S(verdescriptor)) //System?
				{
					switch (verdescriptor.desc.AccessRights) //What type?
					{
					case AVL_CODE_EXECUTEONLY_CONFORMING:
					case AVL_CODE_EXECUTEONLY_CONFORMING_ACCESSED:
					case AVL_CODE_EXECUTE_READONLY_CONFORMING:
					case AVL_CODE_EXECUTE_READONLY_CONFORMING_ACCESSED: //Conforming?
						isconforming = 1;
						break;
					default: //Not conforming?
						isconforming = 0;
						break;
					}
				}
				else
				{
					isconforming = 0; //Not conforming!
				}
				if ((MAX((byte)getCPL(), (byte)getRPL(oper1d)) <= (byte)GENERALSEGMENT_DPL(verdescriptor)) || isconforming) //Valid privilege?
				{
					if (unlikely(CPU[activeCPU].modrmstep == 2)) { if (modrm_check32(&params, MODRM_src0, 0|0x40)) return; if (modrm_check32(&params, MODRM_src0, 0|0xA0)) return; } //Abort on fault!
					if (CPU80386_instructionstepwritemodrmdw(2,((verdescriptor.desc.AccessRights<<8)|((verdescriptor.desc.noncallgate_info&0xF0)<<16)),MODRM_src0)) return; //Write our result!
					CPUPROT1
						FLAGW_ZF(1); //We're valid!
					CPUPROT2
				}
				else
				{
					FLAGW_ZF(0); //Not valid!
				}
				break;
			}
		}
		else //Couldn't be loaded?
		{
			//failedlar386:
			if (loadresult == 0)
			{
				invalidresultLAR386:
				FLAGW_ZF(0); //Default: not loaded!
			}
		}
		CPU_apply286cycles(); //Apply the 80286+ cycles!
	CPUPROT2
}

extern byte protection_PortRightsLookedup; //Are the port rights looked up?
void CPU386_OP0F03() //LSL /r
{
	uint_32 limit;
	byte isconforming = 1;
	SEGMENT_DESCRIPTOR verdescriptor;
	sbyte loadresult;
	if (getcpumode() != CPU_MODE_PROTECTED)
	{
		unkOP0F_286(); //We're not recognized in real mode!
		return;
	}
	modrm_generateInstructionTEXT("LSL", 32, 0, PARAM_MODRM_01); //Our instruction text!
	if (unlikely(CPU[activeCPU].modrmstep == 0)) { if (modrm_check32(&params, MODRM_src1, 1|0x40)) return; if (modrm_check32(&params, MODRM_src1, 1|0xA0)) return; } //Abort on fault!
	if (CPU80386_instructionstepreadmodrmdw(0,&oper1d,MODRM_src1)) return; //Read the segment to check!
	CPUPROT1
		if ((loadresult = LOADDESCRIPTOR(-1, oper1d, &verdescriptor,0))==1) //Load the descriptor!
		{
			/*
			if ((loadresult = touchSegment(-1, oper1d, &verdescriptor, 0)) != 1) //Errored out during touching?
			{
				goto failedlsl386;
			}
			*/
			if ((oper1d & 0xFFFC) == 0) //NULL segment selector?
			{
				goto invalidresultLSL386;
			}
			protection_PortRightsLookedup = (SEGDESC_NONCALLGATE_G(verdescriptor)&CPU[activeCPU].G_Mask); //What granularity are we?
			switch (GENERALSEGMENT_TYPE(verdescriptor))
			{
			case AVL_SYSTEM_RESERVED_0: //Invalid type?
			case AVL_SYSTEM_INTERRUPTGATE16BIT:
			case AVL_SYSTEM_TRAPGATE16BIT:
			case AVL_SYSTEM_RESERVED_1:
			case AVL_SYSTEM_RESERVED_2:
			case AVL_SYSTEM_RESERVED_3:
			case AVL_SYSTEM_INTERRUPTGATE32BIT:
			case AVL_SYSTEM_TRAPGATE32BIT:
				if (GENERALSEGMENT_S(verdescriptor) == 0) //System?
				{
					FLAGW_ZF(0); //Invalid descriptor type!
					break;
				}
			default: //Valid type?
				if (GENERALSEGMENT_S(verdescriptor)) //System?
				{
					switch (verdescriptor.desc.AccessRights) //What type?
					{
					case AVL_CODE_EXECUTEONLY_CONFORMING:
					case AVL_CODE_EXECUTEONLY_CONFORMING_ACCESSED:
					case AVL_CODE_EXECUTE_READONLY_CONFORMING:
					case AVL_CODE_EXECUTE_READONLY_CONFORMING_ACCESSED: //Conforming?
						isconforming = 1;
						break;
					default: //Not conforming?
						isconforming = 0;
						break;
					}
				}
				else
				{
					isconforming = 0; //Not conforming!
				}

				limit = verdescriptor.PRECALCS.limit; //The limit to apply!

				if ((MAX(getCPL(), getRPL(oper1d)) <= GENERALSEGMENT_DPL(verdescriptor)) || isconforming) //Valid privilege?
				{
					if (unlikely(CPU[activeCPU].modrmstep == 2)) { if (modrm_check32(&params, MODRM_src0, 0|0x40)) return; if (modrm_check32(&params, MODRM_src0, 0|0xA0)) return; } //Abort on fault!
					if (CPU80386_instructionstepwritemodrmdw(2,(uint_32)(limit&0xFFFFFFFF),MODRM_src0)) return; //Write our result!
					CPUPROT1
						FLAGW_ZF(1); //We're valid!
					CPUPROT2
				}
				else
				{
					FLAGW_ZF(0); //Not valid!
				}
				break;
			}
		}
		else //Couldn't be loaded?
		{
			//failedlsl386:
			if (loadresult == 0)
			{
				invalidresultLSL386:
				FLAGW_ZF(0); //Default: not loaded!
			}
		}
		CPU_apply286cycles(); //Apply the 80286+ cycles!
	CPUPROT2
}

#include "headers/packed.h" //Packed!
typedef union PACKED
{
	struct
	{
		uint_32 AR;
		uint_32 BASE;
		uint_32 LIMIT;
	};
	uint_32 data[3]; //All our descriptor cache data!
} DESCRIPTORCACHE386;
#include "headers/endpacked.h" //Finished!

#include "headers/packed.h" //Packed!
typedef union PACKED
{
	struct
	{
		uint_32 AR;
		uint_32 BASE;
		uint_32 LIMIT;
	};
	uint_32 data[3];
} DTRdata386;
#include "headers/endpacked.h" //Finished!

void CPU386_LOADALL_LoadDescriptor(DESCRIPTORCACHE386 *source, sword segment)
{
	CPU[activeCPU].SEG_DESCRIPTOR[segment].desc.limit_low = (source->LIMIT&0xFFFF);
	CPU[activeCPU].SEG_DESCRIPTOR[segment].desc.noncallgate_info = ((source->AR&0xF00>>4)|((source->LIMIT>>16)&0xF)); //Full high limit information and remaining rights data!
	CPU[activeCPU].SEG_DESCRIPTOR[segment].desc.base_low = (source->BASE&0xFFFF);
	CPU[activeCPU].SEG_DESCRIPTOR[segment].desc.base_mid = ((source->BASE>>16)&0xFF); //Mid is High base in the descriptor(286 only)!
	CPU[activeCPU].SEG_DESCRIPTOR[segment].desc.base_high = (source->BASE>>24); //Full 32-bits are used for the base!
	CPU[activeCPU].SEG_DESCRIPTOR[segment].desc.AccessRights = source->AR; //Access rights is completely used. Present being 0 makes the register unfit to read (#GP is fired).
	CPU_calcSegmentPrecalcs(&CPU[activeCPU].SEG_DESCRIPTOR[segment]); //Calculate the precalcs!
}

byte LOADALL386_checkMMUaccess(word segment, uint_64 offset, byte readflags, byte CPL, byte is_offset16, byte subbyte) //Difference with normal checks: No segment is used for the access: it's a direct memory access!
{
	INLINEREGISTER uint_32 realaddress;
	if (EMULATED_CPU<=CPU_NECV30) return 0; //No checks are done in the old processors!

	if ((readflags & 0x10) == 0)
	{
		if (unlikely(FLAGREGR_AC(CPU[activeCPU].registers) && (CPU[activeCPU].registers->CR0 & 0x40000) && (EMULATED_CPU >= CPU_80486) && (getCPL() == 3) && (
			((offset & 7) && (subbyte == 0x20)) || ((offset & 3) && (subbyte == 0x10)) || ((offset & 1) && (subbyte == 0x8))
			))) //Aligment enforced and wrong? Don't apply on internal accesses!
		{
			CPU_AC(0); //Alignment DWORD check fault!
			return 1; //Error out!
		}
	}

	//Check for paging and debugging next!
	realaddress = ((uint_64)segment<<4)+offset; //Real adress, 80386 way!

	if ((readflags & 0x20) == 0)
	{
		switch (readflags) //What kind of flags?
		{
		case 0: //Data Write?
			if (unlikely(checkProtectedModeDebugger(realaddress, PROTECTEDMODEDEBUGGER_TYPE_DATAWRITE))) return 1; //Error out!
			break;
		case 1: //Data Read?
			if (unlikely(checkProtectedModeDebugger(realaddress, PROTECTEDMODEDEBUGGER_TYPE_DATAREAD))) return 1; //Error out!
			break;
		case 3: //Opcode read?
			if (unlikely(checkProtectedModeDebugger(realaddress, PROTECTEDMODEDEBUGGER_TYPE_EXECUTION))) return 1; //Error out!
			break;
		case 2: //Unknown?
		default: //Unknown? Unsupported!
			break;
		}
	}

	if ((readflags & 0x40) == 0)
	{
		if (checkDirectMMUaccess(realaddress, readflags, CPL)) //Failure in the Paging Unit?
		{
			return 1; //Error out!
		}
	}

	//We're valid?
	return 0; //We're a valid access for both MMU and Paging! Allow this instruction to execute!
}

#include "headers/packed.h" //Packed
static union PACKED
{
	struct
	{
		uint_32 CR0;
		uint_32 EFLAGS;
		uint_32 EIP;
		uint_32 EDI;
		uint_32 ESI;
		uint_32 EBP;
		uint_32 ESP;
		uint_32 EBX;
		uint_32 EDX;
		uint_32 ECX;
		uint_32 EAX;
		uint_32 DR6;
		uint_32 DR7;
		uint_32 TR;
		uint_32 LDTR;
		uint_32 GS;
		uint_32 FS;
		uint_32	DS;
		uint_32 SS;
		uint_32 CS;
		uint_32 ES;
		DESCRIPTORCACHE386 TRdescriptor;
		DTRdata386 IDTR;
		DTRdata386 GDTR;
		DESCRIPTORCACHE386 LDTRdescriptor;
		DESCRIPTORCACHE386 GSdescriptor;
		DESCRIPTORCACHE386 FSdescriptor;
		DESCRIPTORCACHE386 DSdescriptor;
		DESCRIPTORCACHE386 SSdescriptor;
		DESCRIPTORCACHE386 CSdescriptor;
		DESCRIPTORCACHE386 ESdescriptor;
	} fields; //Fields
	uint_32 datad[0x33]; //Our data size!
} LOADALL386DATA;
#include "headers/endpacked.h" //End packed!

uint_32 loadall386loader[0x33]; //Loader data!

void CPU386_OP0F07() //Undocumented LOADALL instruction
{
	word readindex; //Our read index for all reads that are required!

	if (unlikely(CPU[activeCPU].instructionstep==0)) //First step? Start Request!
	{	
		if (getCPL() && (getcpumode()!=CPU_MODE_REAL)) //We're protected by CPL!
		{
			unkOP0F_286(); //Raise an error!
			return;
		}
		memset(&LOADALL386DATA,0,sizeof(LOADALL386DATA)); //Init the structure to be used as a buffer!
		for (readindex=0;readindex<NUMITEMS(LOADALL386DATA.datad);++readindex)
		{
			if (LOADALL386_checkMMUaccess(REG_ES,((REG_EDI+(readindex<<2))&CPU[activeCPU].address_size),1|0x40,getCPL(),1,0|0x10)) return; //Abort on fault!
			if (LOADALL386_checkMMUaccess(REG_ES,((REG_EDI+(readindex<<2))&CPU[activeCPU].address_size)+3,1|0x40,getCPL(),1,3|0x10)) return; //Abort on fault!
		}
		for (readindex = 0; readindex < NUMITEMS(LOADALL386DATA.datad); ++readindex)
		{
			if (LOADALL386_checkMMUaccess(REG_ES, ((REG_EDI + (readindex << 2))&CPU[activeCPU].address_size), 1 | 0xA0, getCPL(), 1, 0 | 0x10)) return; //Abort on fault!
			if (LOADALL386_checkMMUaccess(REG_ES, ((REG_EDI + (readindex << 2))&CPU[activeCPU].address_size) + 3, 1 | 0xA0, getCPL(), 1, 3 | 0x10)) return; //Abort on fault!
		}
		++CPU[activeCPU].instructionstep; //Finished check!
	}

	//Load the data from the used location!

	//Actually use ES and not the descriptor? Not quite known how to handle this with protection! Use ES literal for now!
	for (readindex=0;readindex<NUMITEMS(loadall386loader);++readindex) //Load all remaining data in default byte order!
	{
		if (CPU80386_instructionstepreaddirectdw((byte)(readindex<<1),-4,REG_ES,(REG_EDI+(readindex<<2)),&loadall386loader[readindex],0)) return; //Access memory directly through the BIU! Read the data to load from memory! Take care of any conversion needed!
	}
	for (readindex = 0; readindex < MIN(NUMITEMS(LOADALL386DATA.datad),NUMITEMS(loadall386loader)); ++readindex)
	{
		LOADALL386DATA.datad[readindex] = loadall386loader[readindex]; //Transfer to the direct buffer!
	}

	//Load all registers and caches, ignore any protection normally done(not checked during LOADALL)!
	//Plain registers!
	CPU[activeCPU].registers->CR0 = LOADALL386DATA.fields.CR0; //MSW! We can reenter real mode by clearing bit 0(Protection Enable bit), just not on the 80286!
	REG_TR = LOADALL386DATA.fields.TR; //TR
	REG_EFLAGS = LOADALL386DATA.fields.EFLAGS; //FLAGS
	REG_EIP = LOADALL386DATA.fields.EIP; //IP
	REG_LDTR = LOADALL386DATA.fields.LDTR; //LDT
	REG_DS = LOADALL386DATA.fields.DS; //DS
	REG_SS = LOADALL386DATA.fields.SS; //SS
	REG_CS = LOADALL386DATA.fields.CS; //CS
	REG_ES = LOADALL386DATA.fields.ES; //ES
	REG_EDI = LOADALL386DATA.fields.EDI; //DI
	REG_ESI = LOADALL386DATA.fields.ESI; //SI
	REG_EBP = LOADALL386DATA.fields.EBP; //BP
	REG_ESP = LOADALL386DATA.fields.ESP; //SP
	REG_EBX = LOADALL386DATA.fields.EBX; //BX
	REG_EDX = LOADALL386DATA.fields.EDX; //CX
	REG_ECX = LOADALL386DATA.fields.ECX; //DX
	REG_EAX = LOADALL386DATA.fields.EAX; //AX
	updateCPUmode(); //We're updating the CPU mode if needed, since we're reloading CR0 and FLAGS!

	//GDTR/IDTR registers!
	CPU[activeCPU].registers->GDTR.base = LOADALL386DATA.fields.GDTR.BASE; //Base!
	CPU[activeCPU].registers->GDTR.limit = LOADALL386DATA.fields.GDTR.LIMIT; //Limit
	CPU[activeCPU].registers->IDTR.base = LOADALL386DATA.fields.IDTR.BASE; //Base!
	CPU[activeCPU].registers->IDTR.limit = LOADALL386DATA.fields.IDTR.LIMIT; //Limit

	//Load all descriptors directly without checks!
	CPU386_LOADALL_LoadDescriptor(&LOADALL386DATA.fields.ESdescriptor,CPU_SEGMENT_ES); //ES descriptor!
	CPU386_LOADALL_LoadDescriptor(&LOADALL386DATA.fields.CSdescriptor,CPU_SEGMENT_CS); //CS descriptor!
	CPU386_LOADALL_LoadDescriptor(&LOADALL386DATA.fields.SSdescriptor,CPU_SEGMENT_SS); //SS descriptor!
	CPU386_LOADALL_LoadDescriptor(&LOADALL386DATA.fields.DSdescriptor,CPU_SEGMENT_DS); //DS descriptor!
	CPU386_LOADALL_LoadDescriptor(&LOADALL386DATA.fields.LDTRdescriptor,CPU_SEGMENT_LDTR); //LDT descriptor!
	CPU386_LOADALL_LoadDescriptor(&LOADALL386DATA.fields.TRdescriptor,CPU_SEGMENT_TR); //TSS descriptor!
	CPU[activeCPU].CPL = GENERALSEGMENT_DPL(CPU[activeCPU].SEG_DESCRIPTOR[CPU_SEGMENT_SS]); //DPL determines CPL!
	CPU_apply286cycles(); //Apply the 80286+ cycles!
	CPU_flushPIQ(-1); //We're jumping to another address!
}

extern byte didJump; //Did we jump?

//New: 16-bit and 32-bit variants of OP70-7F as a 0F opcode!
//16-bits variant
void CPU80386_OP0F80_16() { INLINEREGISTER sword rel16;/*JO rel16: (OF=1)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JO", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_OF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F81_16() { INLINEREGISTER sword rel16;/*JNO rel16 : (OF=0)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JNO", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (!FLAG_OF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F82_16() { INLINEREGISTER sword rel16;/*JC rel16: (CF=1)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JC", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_CF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F83_16() { INLINEREGISTER sword rel16;/*JNC rel16 : (CF=0)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JNC", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (!FLAG_CF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F84_16() { INLINEREGISTER sword rel16;/*JZ rel16: (ZF=1)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JZ", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_ZF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F85_16() { INLINEREGISTER sword rel16;/*JNZ rel16 : (ZF=0)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JNZ", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (!FLAG_ZF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F86_16() { INLINEREGISTER sword rel16;/*JNA rel16 : (CF=1|ZF=1)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JBE", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_CF || FLAG_ZF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F87_16() { INLINEREGISTER sword rel16;/*JA rel16: (CF=0&ZF=0)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JNBE", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (!(FLAG_CF | FLAG_ZF)) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F88_16() { INLINEREGISTER sword rel16;/*JS rel16: (SF=1)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JS", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_SF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F89_16() { INLINEREGISTER sword rel16;/*JNS rel16 : (SF=0)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JNS", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (!FLAG_SF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F8A_16() { INLINEREGISTER sword rel16;/*JP rel16 : (PF=1)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JP", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_PF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F8B_16() { INLINEREGISTER sword rel16;/*JNP rel16 : (PF=0)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JNP", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (!FLAG_PF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F8C_16() { INLINEREGISTER sword rel16;/*JL rel16: (SF!=OF)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JL", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_SF != FLAG_OF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F8D_16() { INLINEREGISTER sword rel16;/*JGE rel16 : (SF=OF)*/ rel16 = imm16(); modrm_generateInstructionTEXT("JGE", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_SF == FLAG_OF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F8E_16() { INLINEREGISTER sword rel16;/*JLE rel16 : (ZF|(SF!=OF))*/ rel16 = imm16(); modrm_generateInstructionTEXT("JLE", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if ((FLAG_SF != FLAG_OF) || FLAG_ZF) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F8F_16() { INLINEREGISTER sword rel16;/*JG rel16: ((ZF=0)&&(SF=OF))*/ rel16 = imm16(); modrm_generateInstructionTEXT("JG", 0, ((REG_EIP + rel16)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if ((!FLAG_ZF) && (FLAG_SF == FLAG_OF)) { CPU_JMPrel((int_32)rel16,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
//32-bits variant
void CPU80386_OP0F80_32() { INLINEREGISTER int_32 rel32;/*JO rel32: (OF=1)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JO", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_OF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F81_32() { INLINEREGISTER int_32 rel32;/*JNO rel32 : (OF=0)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JNO", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (!FLAG_OF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F82_32() { INLINEREGISTER int_32 rel32;/*JC rel32: (CF=1)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JC", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_CF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F83_32() { INLINEREGISTER int_32 rel32;/*JNC rel32 : (CF=0)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JNC", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (!FLAG_CF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F84_32() { INLINEREGISTER int_32 rel32;/*JZ rel32: (ZF=1)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JZ", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_ZF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F85_32() { INLINEREGISTER int_32 rel32;/*JNZ rel32 : (ZF=0)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JNZ", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (!FLAG_ZF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F86_32() { INLINEREGISTER int_32 rel32;/*JNA rel32 : (CF=1|ZF=1)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JBE", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_CF || FLAG_ZF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F87_32() { INLINEREGISTER int_32 rel32;/*JA rel32: (CF=0&ZF=0)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JNBE", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (!(FLAG_CF | FLAG_ZF)) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F88_32() { INLINEREGISTER int_32 rel32;/*JS rel32: (SF=1)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JS", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_SF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F89_32() { INLINEREGISTER int_32 rel32;/*JNS rel32 : (SF=0)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JNS", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (!FLAG_SF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/ didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F8A_32() { INLINEREGISTER int_32 rel32;/*JP rel32 : (PF=1)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JP", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_PF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F8B_32() { INLINEREGISTER int_32 rel32;/*JNP rel32 : (PF=0)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JNP", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (!FLAG_PF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F8C_32() { INLINEREGISTER int_32 rel32;/*JL rel32: (SF!=OF)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JL", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_SF != FLAG_OF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F8D_32() { INLINEREGISTER int_32 rel32;/*JGE rel32 : (SF=OF)*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JGE", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if (FLAG_SF == FLAG_OF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F8E_32() { INLINEREGISTER int_32 rel32;/*JLE rel32 : (ZF|(SF!=OF))*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JLE", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if ((FLAG_SF != FLAG_OF) || FLAG_ZF) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }
void CPU80386_OP0F8F_32() { INLINEREGISTER int_32 rel32;/*JG rel32: ((ZF=0)&&(SF=OF))*/ rel32 = imm32s(); modrm_generateInstructionTEXT("JG", 0, ((REG_EIP + rel32)&CPU_EIPmask(0)), CPU_EIPSize(0)); /* JUMP to destination? */ if ((!FLAG_ZF) && (FLAG_SF == FLAG_OF)) { CPU_JMPrel((int_32)rel32,0); /* JUMP to destination? */ CPU_flushPIQ(-1); /*We're jumping to another address*/  didJump = 1; if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 16; CPU[activeCPU].cycles_stallBIU += CPU[activeCPU].cycles_OP; /*Stall the BIU completely now!*/ } /* Branch taken */ } else { if (CPU_apply286cycles() == 0) /* No 80286+ cycles instead? */ { CPU[activeCPU].cycles_OP += 4; /* Branch not taken */ } } }

//MOV [C/D]Rn instructions

OPTINLINE byte allowCRDRaccess()
{
	return ((getCPL()==0) || (getcpumode()==CPU_MODE_REAL)); //Do we allow access?
}

void CPU80386_OP0F_MOVCRn_modrmmodrm() {modrm_generateInstructionTEXT("MOV",32,0,PARAM_MODRM_01); if (unlikely(allowCRDRaccess()==0)) {THROWDESCGP(0,0,0); return;} uint_32 val=modrm_read32(&params,MODRM_src1); if (((val&(CR0_PE|CR0_PG))==CR0_PG) && (MODRM_src0==0) && (modrm_addr32(&params,MODRM_src0,0)==&CPU[activeCPU].registers->CR0)) {THROWDESCGP(0,0,0); return;/* Enabling Paging whilst disabling protection is forbidden! */} modrm_write32(&params,MODRM_src0,val); CPU_apply286cycles(); /* Apply cycles */ } //MOV /r CRn/r32,r32/CRn
void CPU80386_OP0F_MOVDRn_modrmmodrm() {modrm_generateInstructionTEXT("MOV",32,0,PARAM_MODRM_01); if (unlikely(allowCRDRaccess()==0)) {THROWDESCGP(0,0,0); return;} modrm_write32(&params,MODRM_src0,modrm_read32(&params,MODRM_src1)); CPU_apply286cycles(); /* Apply cycles */ } //MOV /r DRn/r32,r32/DRn
void CPU80386_OP0F_MOVTRn_modrmmodrm() {modrm_generateInstructionTEXT("MOV",32,0,PARAM_MODRM_01); if (unlikely(allowCRDRaccess()==0)) {THROWDESCGP(0,0,0); return;} modrm_write32(&params,MODRM_src0,modrm_read32(&params,MODRM_src1)); CPU_apply286cycles(); /* Apply cycles */ } //MOV /r TRn/r32,r32/TRn

//SETCC instructions

/*

Info for different conditions:
O: FLAG_OF
NO: !FLAG_OF
C: FLAG_CF
NC: !FLAG_CF
Z: FLAG_ZF
NZ: !FLAG_ZF
BE: (FLAG_CF||FLAG_ZF)
A: (!FLAG_CF && !FLAG_ZF)
S: FLAG_SF
NS: !FLAG_SF
P: FLAG_PF
NP: !FLAG_PF
L: (FLAG_SF!=FLAG_OF)
GE: (FLAG_SF==FLAG_OF)
LE: ((FLAG_SF!=FLAG_OF) || FLAG_ZF)
G: (!FLAG_ZF && (FLAG_SF==FLAG_OF))

*/

void CPU80386_OP0F90() {modrm_generateInstructionTEXT("SETO",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,FLAG_OF,MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETO r/m8
void CPU80386_OP0F91() {modrm_generateInstructionTEXT("SETNO",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,(FLAG_OF^1),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETNO r/m8
void CPU80386_OP0F92() {modrm_generateInstructionTEXT("SETC",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,FLAG_CF,MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETC r/m8
void CPU80386_OP0F93() {modrm_generateInstructionTEXT("SETNC",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,(FLAG_CF^1),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETAE r/m8
void CPU80386_OP0F94() {modrm_generateInstructionTEXT("SETZ",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,FLAG_ZF,MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETE r/m8
void CPU80386_OP0F95() {modrm_generateInstructionTEXT("SETNZ",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,(FLAG_ZF^1),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETNE r/m8
void CPU80386_OP0F96() {modrm_generateInstructionTEXT("SETBE",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,(FLAG_CF|FLAG_ZF),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETNA r/m8
void CPU80386_OP0F97() {modrm_generateInstructionTEXT("SETNBE",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,((FLAG_CF|FLAG_ZF)^1),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETA r/m8
void CPU80386_OP0F98() {modrm_generateInstructionTEXT("SETS",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,FLAG_SF,MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETS r/m8
void CPU80386_OP0F99() {modrm_generateInstructionTEXT("SETNS",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,(FLAG_SF^1),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETNS r/m8
void CPU80386_OP0F9A() {modrm_generateInstructionTEXT("SETP",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,FLAG_PF,MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETP r/m8
void CPU80386_OP0F9B() {modrm_generateInstructionTEXT("SETNP",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,(FLAG_PF^1),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETNP r/m8
void CPU80386_OP0F9C() {modrm_generateInstructionTEXT("SETL",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,(FLAG_SF^FLAG_OF),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETL r/m8
void CPU80386_OP0F9D() {modrm_generateInstructionTEXT("SETGE",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,((FLAG_SF^FLAG_OF)^1),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETGE r/m8
void CPU80386_OP0F9E() {modrm_generateInstructionTEXT("SETLE",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,((FLAG_SF^FLAG_OF)|FLAG_ZF),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETLE r/m8
void CPU80386_OP0F9F() {modrm_generateInstructionTEXT("SETG",8,0,PARAM_MODRM_0); if (unlikely(CPU[activeCPU].modrmstep==0)) if (modrm_check8(&params,MODRM_src0,0)) return; if (CPU8086_instructionstepwritemodrmb(0,(((FLAG_SF^FLAG_OF)^1)&(FLAG_ZF^1)),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //SETG r/m8

extern byte instructionbufferb, instructionbufferb2; //For 8-bit read storage!
extern word instructionbufferw, instructionbufferw2; //For 16-bit read storage!
extern uint_32 instructionbufferd, instructionbufferd2; //For 32-bit read storage!

//Push/pop FS/GS instructions.
void CPU80386_OP0FA0() {modrm_generateInstructionTEXT("PUSH FS",0,0,PARAM_NONE);/*PUSH FS*/ if (unlikely(CPU[activeCPU].stackchecked==0)) { if (checkStackAccess(1,1,CPU_Operand_size[activeCPU])) return; ++CPU[activeCPU].stackchecked; } if (CPU8086_PUSHw(0,&REG_FS,CPU_Operand_size[activeCPU])) return;/*PUSH FS*/CPU_apply286cycles(); /* Apply cycles */ } //PUSH FS
void CPU80386_OP0FA1() {modrm_generateInstructionTEXT("POP FS",0,0,PARAM_NONE);/*POP FS*/ if (unlikely(CPU[activeCPU].stackchecked==0)) { if (checkStackAccess(1,0,CPU_Operand_size[activeCPU]|2)) return; ++CPU[activeCPU].stackchecked; } if (CPU8086_POPw(0,&instructionbufferw,CPU_Operand_size[activeCPU])) return; if (segmentWritten(CPU_SEGMENT_FS,instructionbufferw,0)) return; CPU_apply286cycles(); /* Apply cycles */ } //POP FS

void CPU80386_OP0FA8() {modrm_generateInstructionTEXT("PUSH GS",0,0,PARAM_NONE);/*PUSH GS*/ if (unlikely(CPU[activeCPU].stackchecked==0)) { if (checkStackAccess(1,1,CPU_Operand_size[activeCPU])) return; ++CPU[activeCPU].stackchecked; } if (CPU8086_PUSHw(0,&REG_GS,CPU_Operand_size[activeCPU])) return;/*PUSH FS*/ CPU_apply286cycles(); /* Apply cycles */ } //PUSH GS
void CPU80386_OP0FA9() {modrm_generateInstructionTEXT("POP GS",0,0,PARAM_NONE);/*POP GS*/ if (unlikely(CPU[activeCPU].stackchecked==0)) { if (checkStackAccess(1,0,CPU_Operand_size[activeCPU]|2)) return; ++CPU[activeCPU].stackchecked; } if (CPU8086_POPw(0,&instructionbufferw,CPU_Operand_size[activeCPU])) return ; if (segmentWritten(CPU_SEGMENT_GS,instructionbufferw,0)) return; CPU_apply286cycles(); /* Apply cycles */ } //POP GS

//L*S instructions

void CPU80386_OP0FB2_16() /*LSS modr/m*/ {modrm_generateInstructionTEXT("LSS",16,0,PARAM_MODRM_01); CPU8086_internal_LXS(CPU_SEGMENT_SS); /*Load new SS!*/ } //LSS /r r16,m16:16
void CPU80386_OP0FB2_32() /*LSS modr/m*/ {modrm_generateInstructionTEXT("LSS",32,0,PARAM_MODRM_01); CPU80386_internal_LXS(CPU_SEGMENT_SS); /*Load new SS!*/ } //LSS /r r32,m16:32

void CPU80386_OP0FB4_16() /*LFS modr/m*/ {modrm_generateInstructionTEXT("LFS",16,0,PARAM_MODRM_01); CPU8086_internal_LXS(CPU_SEGMENT_FS); /*Load new FS!*/ } //LFS /r r16,m16:16
void CPU80386_OP0FB4_32() /*LFS modr/m*/ {modrm_generateInstructionTEXT("LFS",32,0,PARAM_MODRM_01); CPU80386_internal_LXS(CPU_SEGMENT_FS); /*Load new FS!*/ } //LFS /r r32,m16:32

void CPU80386_OP0FB5_16() /*LGS modr/m*/ {modrm_generateInstructionTEXT("LGS",16,0,PARAM_MODRM_01); CPU8086_internal_LXS(CPU_SEGMENT_GS); /*Load new GS!*/ } //LGS /r r16,m16:16
void CPU80386_OP0FB5_32() /*LGS modr/m*/ {modrm_generateInstructionTEXT("LGS",32,0,PARAM_MODRM_01); CPU80386_internal_LXS(CPU_SEGMENT_GS); /*Load new GS!*/ } //LGS /r r32,m16:32

//Special debugger support for the following MOV[S/Z]X instructions.

OPTINLINE void modrm_actualdebuggerSZX(char *instruction)
{
	char result[256];
	cleardata(&result[0],sizeof(result));
	safestrcpy(result,sizeof(result),instruction); //Set the instruction!
	safestrcat(result,sizeof(result)," %s,%s"); //2 params!
	debugger_setcommand(result,modrm_param1,modrm_param2);
}

OPTINLINE void modrm_debugger16_8(char *instruction)
{
	if (unlikely(cpudebugger))
	{
		cleardata(&modrm_param1[0],sizeof(modrm_param1));
		cleardata(&modrm_param2[0],sizeof(modrm_param2));
		modrm_text16(&params,MODRM_src0,&modrm_param1[0]);
		modrm_text8(&params,MODRM_src1,&modrm_param2[0]);
		modrm_actualdebuggerSZX(instruction); //Actual debugger call!
	}
}

OPTINLINE void modrm_debugger32_8(char *instruction)
{
	if (unlikely(cpudebugger))
	{
		cleardata(&modrm_param1[0],sizeof(modrm_param1));
		cleardata(&modrm_param2[0],sizeof(modrm_param2));
		modrm_text32(&params,MODRM_src0,&modrm_param1[0]);
		modrm_text8(&params,MODRM_src1,&modrm_param2[0]);
		modrm_actualdebuggerSZX(instruction); //Actual debugger call!
	}
}

OPTINLINE void modrm_debugger16_16(char *instruction)
{
	if (unlikely(cpudebugger))
	{
		cleardata(&modrm_param1[0],sizeof(modrm_param1));
		cleardata(&modrm_param2[0],sizeof(modrm_param2));
		modrm_text16(&params,MODRM_src0,&modrm_param1[0]);
		modrm_text16(&params,MODRM_src1,&modrm_param2[0]);
		modrm_actualdebuggerSZX(instruction); //Actual debugger call!
	}
}


OPTINLINE void modrm_debugger32_16(char *instruction)
{
	if (unlikely(cpudebugger))
	{
		cleardata(&modrm_param1[0],sizeof(modrm_param1));
		cleardata(&modrm_param2[0],sizeof(modrm_param2));
		modrm_text32(&params,MODRM_src0,&modrm_param1[0]);
		modrm_text16(&params,MODRM_src1,&modrm_param2[0]);
		modrm_actualdebuggerSZX(instruction); //Actual debugger call!
	}
}

//MOVS/ZX instructions.

void CPU80386_OP0FB6_16() {modrm_debugger16_8("MOVZX"); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check8(&params,MODRM_src1,1|0x40)) return; if (modrm_check16(&params,MODRM_src0,0|0x40)) return; if (modrm_check8(&params,MODRM_src1,1|0xA0)) return; if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmb(0,&instructionbufferb,MODRM_src1)) return; if (CPU8086_instructionstepwritemodrmw(2,(word)instructionbufferb,MODRM_src0,0)) return; CPU_apply286cycles(); /* Apply cycles */ } //MOVZX /r r16,r/m8
void CPU80386_OP0FB6_32() {modrm_debugger32_8("MOVZX"); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check8(&params,MODRM_src1,1|0x40)) return; if (modrm_check32(&params,MODRM_src0,0|0x40)) return; if (modrm_check8(&params,MODRM_src1,1|0xA0)) return; if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmb(0,&instructionbufferb,MODRM_src1)) return; if (CPU80386_instructionstepwritemodrmdw(2,(uint_32)instructionbufferb,MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //MOVZX /r r32,r/m8

void CPU80386_OP0FB7_16() {modrm_debugger16_16("MOVZX"); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check16(&params,MODRM_src1,1|0x40)) return; if (modrm_check16(&params,MODRM_src0,0|0x40)) return; if (modrm_check16(&params,MODRM_src1,1|0xA0)) return; if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; if (CPU8086_instructionstepwritemodrmw(2,(word)instructionbufferw,MODRM_src0,0)) return; CPU_apply286cycles(); /* Apply cycles */ } //MOVZX /r r16,r/m16
void CPU80386_OP0FB7_32() {modrm_debugger32_16("MOVZX"); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check16(&params,MODRM_src1,1|0x40)) return; if (modrm_check32(&params,MODRM_src0,0|0x40)) return; if (modrm_check16(&params,MODRM_src1,1|0xA0)) return; if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; if (CPU80386_instructionstepwritemodrmdw(2,(uint_32)instructionbufferw,MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //MOVZX /r r32,r/m16

void CPU80386_OP0FBE_16() {modrm_debugger16_8("MOVSX"); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check8(&params,MODRM_src1,1|0x40)) return; if (modrm_check16(&params,MODRM_src0,0|0x40)) return; if (modrm_check8(&params,MODRM_src1,1|0xA0)) return; if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmb(0,&instructionbufferb,MODRM_src1)) return; if (CPU8086_instructionstepwritemodrmw(2,signed2unsigned16((sword)unsigned2signed8(instructionbufferb)),MODRM_src0,0)) return; CPU_apply286cycles(); /* Apply cycles */ } //MOVSX /r r16,r/m8
void CPU80386_OP0FBE_32() {modrm_debugger32_8("MOVSX"); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check8(&params,MODRM_src1,1|0x40)) return; if (modrm_check32(&params,MODRM_src0,0|0x40)) return; if (modrm_check8(&params,MODRM_src1,1|0xA0)) return; if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmb(0,&instructionbufferb,MODRM_src1)) return; if (CPU80386_instructionstepwritemodrmdw(2,signed2unsigned32((int_32)unsigned2signed8(instructionbufferb)),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //MOVSX /r r32,r/m8

void CPU80386_OP0FBF_16() {modrm_debugger16_16("MOVSX"); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check16(&params,MODRM_src1,1|0x40)) return; if (modrm_check16(&params,MODRM_src0,0|0x40)) return; if (modrm_check16(&params,MODRM_src1,1|0xA0)) return; if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; if (CPU8086_instructionstepwritemodrmw(2,signed2unsigned16((sword)unsigned2signed16(instructionbufferw)),MODRM_src0,0)) return; CPU_apply286cycles(); /* Apply cycles */ } //MOVSX /r r16,r/m16
void CPU80386_OP0FBF_32() {modrm_debugger32_16("MOVSX"); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check16(&params,MODRM_src1,1|0x40)) return; if (modrm_check32(&params,MODRM_src0,0|0x40)) return; if (modrm_check16(&params,MODRM_src1,1|0xA0)) return; if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; if (CPU80386_instructionstepwritemodrmdw(2,signed2unsigned32((int_32)unsigned2signed16(instructionbufferw)),MODRM_src0)) return; CPU_apply286cycles(); /* Apply cycles */ } //MOVSX /r r32,r/m16

extern byte BST_cnt; //How many of bit scan/test (forward) times are taken?

//0F AA is RSM FLAGS on 386++

//SHL/RD instructions.

word tempSHLRDW;
uint_32 tempSHLRDD;

void CPU80386_SHLD_16(word *dest, word src, byte cnt)
{
	byte shift;
	cnt &= 0x1F;
	BST_cnt = 0; //Count!
	if (cnt) //To actually shift?
	{
		if (!dest) { if (CPU8086_internal_stepreadmodrmw(0,&tempSHLRDW,MODRM_src0)) return; } //Read source if needed!
		else if (CPU[activeCPU].internalinstructionstep==0) tempSHLRDW = *dest;
		if (CPU[activeCPU].internalinstructionstep==0) //Exection step?
		{
			BST_cnt = cnt; //Count!
			for (shift = 1; shift <= cnt; shift++)
			{
				if (tempSHLRDW & 0x8000) FLAGW_CF(1); else FLAGW_CF(0);
				tempSHLRDW = ((tempSHLRDW << 1) & 0xFFFF)|((src>>15)&1);
				src <<= 1; //Next bit to shift in!
			}
			if (cnt==1) { if (FLAG_CF == (tempSHLRDW >> 15)) FLAGW_OF(0); else FLAGW_OF(1); }
			flag_szp16(tempSHLRDW);
			++CPU[activeCPU].internalinstructionstep;
			CPU_apply286cycles(); /* Apply cycles */
			if (dest==NULL)
			{
				CPU[activeCPU].executed = 0; //Still running!
				return;
			}
		}
		if (dest)
		{
			*dest = tempSHLRDW;
		}
		else
		{
			if (CPU8086_internal_stepwritemodrmw(2,tempSHLRDW,MODRM_src0,0)) return;
		}
	}
}

void CPU80386_SHLD_32(uint_32 *dest, uint_32 src, byte cnt)
{
	byte shift;
	cnt &= 0x1F;
	BST_cnt = 0; //Count!
	if (cnt)
	{
		if (!dest) { if (CPU80386_internal_stepreadmodrmdw(0,&tempSHLRDD,MODRM_src0)) return; } //Read source if needed!
		else if (CPU[activeCPU].internalinstructionstep==0) tempSHLRDD = *dest;
		if (CPU[activeCPU].internalinstructionstep==0) //Exection step?
		{
			BST_cnt = cnt; //Count!
			for (shift = 1; shift <= cnt; shift++)
			{
				if (tempSHLRDD & 0x80000000) FLAGW_CF(1); else FLAGW_CF(0);
				tempSHLRDD = ((tempSHLRDD << 1) & 0xFFFFFFFF)|((src>>31)&1);
				src <<= 1; //Next bit to shift in!
			}
			if (cnt==1) { if (FLAG_CF == (tempSHLRDD >> 31)) FLAGW_OF(0); else FLAGW_OF(1); }
			flag_szp32(tempSHLRDD);
			++CPU[activeCPU].internalinstructionstep;
			CPU_apply286cycles(); /* Apply cycles */
			if (dest==NULL)
			{
				CPU[activeCPU].executed = 0; //Still running!
				return;
			}
		}
		if (dest)
		{
			*dest = tempSHLRDD;
		}
		else
		{
			if (CPU80386_internal_stepwritemodrmdw(2,tempSHLRDD,MODRM_src0)) return;
		}
	}
}

void CPU80386_SHRD_16(word *dest, word src, byte cnt)
{
	byte shift;
	cnt &= 0x1F;
	BST_cnt = 0; //Count!
	if (cnt)
	{
		if (!dest) { if (CPU8086_internal_stepreadmodrmw(0,&tempSHLRDW,MODRM_src0)) return; } //Read source if needed!
		else if (CPU[activeCPU].internalinstructionstep==0) tempSHLRDW = *dest;
		if (CPU[activeCPU].internalinstructionstep==0) //Exection step?
		{
			BST_cnt = cnt; //Count!
			if (cnt == 1) FLAGW_OF(((tempSHLRDW & 0x8000) ^ ((src & 1) << 15)) ? 1 : 0);
			for (shift = 1; shift <= cnt; shift++)
			{
				FLAGW_CF(tempSHLRDW & 1);
				tempSHLRDW = ((tempSHLRDW >> 1)|((src&1)<<15));
				src >>= 1; //Next bit to shift in!
			}
			flag_szp16(tempSHLRDW);
			++CPU[activeCPU].internalinstructionstep;
			CPU_apply286cycles(); /* Apply cycles */
			if (dest==NULL)
			{
				CPU[activeCPU].executed = 0; //Still running!
				return;
			}
		}
		if (dest)
		{
			*dest = tempSHLRDW;
		}
		else
		{
			if (CPU8086_internal_stepwritemodrmw(2,tempSHLRDW,MODRM_src0,0)) return;
		}
	}
}


void CPU80386_SHRD_32(uint_32 *dest, uint_32 src, byte cnt)
{
	byte shift;
	cnt &= 0x1F;
	BST_cnt = 0; //Count!
	if (cnt)
	{
		if (!dest) { if (CPU80386_internal_stepreadmodrmdw(0,&tempSHLRDD,MODRM_src0)) return; } //Read source if needed!
		else if (CPU[activeCPU].internalinstructionstep==0) tempSHLRDD = *dest;
		if (CPU[activeCPU].internalinstructionstep==0) //Exection step?
		{
			BST_cnt = cnt; //Count!
			if (cnt==1) FLAGW_OF(((tempSHLRDD & 0x80000000)^((src&1)<<31)) ? 1 : 0);
			for (shift = 1; shift <= cnt; shift++)
			{
				FLAGW_CF(tempSHLRDD & 1);
				tempSHLRDD = ((tempSHLRDD >> 1)|((src&1)<<31));
				src >>= 1; //Next bit to shift in!
			}
			flag_szp32(tempSHLRDD);
			++CPU[activeCPU].internalinstructionstep;
			CPU_apply286cycles(); /* Apply cycles */
			if (dest==NULL)
			{
				CPU[activeCPU].executed = 0; //Still running!
				return;
			}
		}
		if (dest)
		{
			*dest = tempSHLRDD;
		}
		else
		{
			if (CPU80386_internal_stepwritemodrmdw(2,tempSHLRDD,MODRM_src0)) return;
		}
	}
}

void CPU80386_OP0FA4_16() {modrm_generateInstructionTEXT("SHLD",16,immb,PARAM_MODRM_01_IMM8); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check16(&params,MODRM_src1,1|0x40)) return; if (modrm_check16(&params,MODRM_src0,0|0x40)) return; if (modrm_check16(&params,MODRM_src1,1|0xA0)) return; if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; CPU80386_SHLD_16(modrm_addr16(&params,MODRM_src0,0),instructionbufferw,immb);} //SHLD /r r/m16,r16,imm8
void CPU80386_OP0FA4_32() {modrm_generateInstructionTEXT("SHLD",32,immb,PARAM_MODRM_01_IMM8); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check32(&params,MODRM_src1,1|0x40)) return; if (modrm_check32(&params,MODRM_src0,0|0x40)) return; if (modrm_check32(&params,MODRM_src1,1|0xA0)) return; if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; } if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_SHLD_32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,immb);} //SHLD /r r/m32,r32,imm8
void CPU80386_OP0FA5_16() {modrm_generateInstructionTEXT("SHLD",16,0,PARAM_MODRM_01_CL); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check16(&params,MODRM_src1,1|0x40)) return; if (modrm_check16(&params,MODRM_src0,0|0x40)) return; if (modrm_check16(&params,MODRM_src1,1|0xA0)) return; if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; CPU80386_SHLD_16(modrm_addr16(&params,MODRM_src0,0),instructionbufferw,REG_CL);} //SHLD /r r/m16,r16,CL
void CPU80386_OP0FA5_32() {modrm_generateInstructionTEXT("SHLD",32,0,PARAM_MODRM_01_CL); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check32(&params,MODRM_src1,1|0x40)) return; if (modrm_check32(&params,MODRM_src0,0|0x40)) return; if (modrm_check32(&params,MODRM_src1,1|0xA0)) return; if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; } if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_SHLD_32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,REG_CL);} //SHLD /r r/m32,r32,CL

void CPU80386_OP0FAC_16() {modrm_generateInstructionTEXT("SHRD",16,immb,PARAM_MODRM_01_IMM8); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check16(&params,MODRM_src1,1|0x40)) return; if (modrm_check16(&params,MODRM_src0,0|0x40)) return; if (modrm_check16(&params,MODRM_src1,1|0xA0)) return; if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; CPU80386_SHRD_16(modrm_addr16(&params,MODRM_src0,0),instructionbufferw,immb);} //SHRD /r r/m16,r16,imm8
void CPU80386_OP0FAC_32() {modrm_generateInstructionTEXT("SHRD",32,immb,PARAM_MODRM_01_IMM8); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check32(&params,MODRM_src1,1|0x40)) return; if (modrm_check32(&params,MODRM_src0,0|0x40)) return; if (modrm_check32(&params,MODRM_src1,1|0xA0)) return; if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; } if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_SHRD_32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,immb);} //SHRD /r r/m32,r32,imm8
void CPU80386_OP0FAD_16() {modrm_generateInstructionTEXT("SHRD",16,0,PARAM_MODRM_01_CL); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check16(&params,MODRM_src1,1|0x40)) return; if (modrm_check16(&params,MODRM_src0,0|0x40)) return; if (modrm_check16(&params,MODRM_src1,1|0xA0)) return; if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; CPU80386_SHRD_16(modrm_addr16(&params,MODRM_src0,0),instructionbufferw,REG_CL);} //SHRD /r r/m16,r16,CL
void CPU80386_OP0FAD_32() {modrm_generateInstructionTEXT("SHRD",32,0,PARAM_MODRM_01_CL); if (unlikely(CPU[activeCPU].modrmstep==0)) { if (modrm_check32(&params,MODRM_src1,1|0x40)) return; if (modrm_check32(&params,MODRM_src0,0|0x40)) return; if (modrm_check32(&params,MODRM_src1,1|0xA0)) return; if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; } if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; CPU80386_SHRD_32(modrm_addr32(&params,MODRM_src0,0),instructionbufferd,REG_CL);} //SHRD /r r/m32,r32,CL

//IMUL instruction

extern uint_32 IMULresult;
void CPU80386_OP0FAF_16() { //IMUL /r r16,r/m16
	modrm_generateInstructionTEXT("IMUL",16,0,PARAM_MODRM12);
	if (unlikely(CPU[activeCPU].modrmstep==0)) //Starting instruction?
	{
		if (modrm_check16(&params,MODRM_src0,0|0x40)) return;
		if (modrm_check16(&params,MODRM_src1,1|0x40)) return;
		if (modrm_check16(&params,MODRM_src0,0|0xA0)) return;
		if (modrm_check16(&params,MODRM_src1,1|0xA0)) return;
	}
	if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src0)) return;
	if (CPU8086_instructionstepreadmodrmw(2,&instructionbufferw2,MODRM_src1)) return;
	if (CPU[activeCPU].instructionstep==0) //Execution step?
	{
		CPU_CIMUL((uint_32)instructionbufferw,16,(uint_32)instructionbufferw2,16,&IMULresult,16); //Execute!
		CPU_apply286cycles(); /* Apply cycles */
		++CPU[activeCPU].instructionstep; //Next step!
		CPU[activeCPU].executed = 0; //Still running!
		return; //Time us!
	}
	if (CPU8086_instructionstepwritemodrmw(4,(IMULresult&0xFFFF),MODRM_src0,0)) return;
}
void CPU80386_OP0FAF_32() { //IMUL /r r32,r/m32
	modrm_generateInstructionTEXT("IMUL",32,0,PARAM_MODRM12);
	if (unlikely(CPU[activeCPU].modrmstep==0)) //Starting instruction?
	{
		if (modrm_check32(&params,MODRM_src0,0|0x40)) return;
		if (modrm_check32(&params,MODRM_src1,1|0x40)) return;
		if (modrm_check32(&params,MODRM_src0,0|0xA0)) return;
		if (modrm_check32(&params,MODRM_src1,1|0xA0)) return;
	}
	if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src0)) return;
	if (CPU80386_instructionstepreadmodrmdw(2,&instructionbufferd2,MODRM_src1)) return;
	if (CPU[activeCPU].instructionstep==0) //Execution step?
	{
		CPU_CIMUL(instructionbufferd,32,instructionbufferd2,32,&IMULresult,32); //Execute!
		CPU_apply286cycles(); /* Apply cycles */
		++CPU[activeCPU].instructionstep; //Next step!
		CPU[activeCPU].executed = 0; //Still running!
		return; //Time us!
	}
	if (CPU80386_instructionstepwritemodrmdw(4,IMULresult,MODRM_src0)) return;
}

//Bit test(and set/clear/complement) instructions

void CPU80386_BT16(word val, word bit)
{
	INLINEREGISTER byte overflow,tempCF,shift;
	INLINEREGISTER uint_32 s;
	BST_cnt = (bit&0xF)+1; //Count!

	FLAGW_CF(0); //Start out with CF cleared!
	s = val; //For processing like RCR!
	overflow = BST_cnt?0:FLAG_OF; //Default: no overflow!
	for (shift = 1; shift <= BST_cnt; shift++) {
		overflow = ((s >> 15)^FLAG_CF);
		tempCF = FLAG_CF;
		FLAGW_CF(s); //Save LSB!
		s = ((s >> 1)&0x7FFFU) | (tempCF << 15);
	}
	if (BST_cnt) FLAGW_OF(overflow);

	CPU_apply286cycles(); /* Apply cycles */
}

void CPU80386_BT32(uint_32 val, uint_32 bit)
{
	INLINEREGISTER byte overflow,tempCF,shift;
	INLINEREGISTER uint_64 s;
	BST_cnt = (bit&0x1F)+1; //Count!

	FLAGW_CF(0); //Start out with CF cleared!
	s = val; //For processing like RCR!
	overflow = BST_cnt?0:FLAG_OF; //Default: no overflow!
	for (shift = 1; shift <= BST_cnt; shift++) {
		overflow = (((s >> 31)&1)^FLAG_CF);
		tempCF = FLAG_CF;
		FLAGW_CF(s); //Save LSB!
		s = ((s >> 1)&0x7FFFFFFFULL) | ((uint_64)tempCF << 31);
	}
	if (BST_cnt) FLAGW_OF(overflow);

	CPU_apply286cycles(); /* Apply cycles */
}

void CPU80386_BTS16(word *val, word bit)
{
	CPU80386_BT16(*val,bit);
	*val |= (1<<(bit&0xF)); //Set!
}

void CPU80386_BTS32(uint_32 *val, uint_32 bit)
{
	CPU80386_BT32(*val,bit);
	*val |= (1<<(bit&0x1F)); //Set!
}

void CPU80386_BTR16(word *val, word bit)
{
	CPU80386_BT16(*val,bit);
	*val &= ~(1<<(bit&0xF)); //Reset!
}

void CPU80386_BTR32(uint_32 *val, uint_32 bit)
{
	CPU80386_BT32(*val,bit);
	*val &= ~(1<<(bit&0x1F)); //Reset!
}

void CPU80386_BTC16(word *val, word bit)
{
	CPU80386_BT16(*val,bit);
	*val ^= (1<<(bit&0xF)); //Complement!
}

void CPU80386_BTC32(uint_32 *val, uint_32 bit)
{
	CPU80386_BT32(*val,bit);
	*val ^= (1<<(bit&0x1F)); //Complement!
}

void CPU80386_OP0FA3_16() { modrm_generateInstructionTEXT("BT", 16, 0, PARAM_MODRM_01); if (CPU8086_instructionstepreadmodrmw(0, &instructionbufferw, MODRM_src1)) return; modrm_addoffset = (int_32)((unsigned2signed16(instructionbufferw) >> 4) << 1); if (unlikely(CPU[activeCPU].modrmstep == 2)) { if (modrm_check16(&params, MODRM_src0, 1|0x40)) return; if (modrm_check16(&params, MODRM_src0, 1|0xA0)) return; } if (CPU8086_instructionstepreadmodrmw(2, &instructionbufferw2, MODRM_src0)) return; CPU80386_BT16(instructionbufferw2, instructionbufferw); } //BT /r r/m16,r16
void CPU80386_OP0FA3_32() { modrm_generateInstructionTEXT("BT", 32, 0, PARAM_MODRM_01); if (CPU80386_instructionstepreadmodrmdw(0, &instructionbufferd, MODRM_src1)) return; modrm_addoffset = (int_32)((unsigned2signed32(instructionbufferd) >> 5) << 2); if (unlikely(CPU[activeCPU].modrmstep == 2)) { if (modrm_check32(&params, MODRM_src0, 1|0x40)) return; if (modrm_check32(&params, MODRM_src0, 1|0xA0)) return; } if (CPU80386_instructionstepreadmodrmdw(2, &instructionbufferd2, MODRM_src0)) return; CPU80386_BT32(instructionbufferd2, instructionbufferd); } //BT /r r/m32,r32

void CPU80386_OP0FAB_16() {modrm_generateInstructionTEXT("BTS",16,0,PARAM_MODRM_01); if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; modrm_addoffset = (int_32)((unsigned2signed16(instructionbufferw)>>4)<<1); if (unlikely(CPU[activeCPU].modrmstep==2)) { if (modrm_check16(&params,MODRM_src0,0|0x40)) return; if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmw(2,&instructionbufferw2,MODRM_src0)) return; if (CPU[activeCPU].instructionstep==0) { CPU80386_BTS16(&instructionbufferw2,instructionbufferw); ++CPU[activeCPU].instructionstep; if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; } } if (CPU8086_instructionstepwritemodrmw(4,instructionbufferw2,MODRM_src0,0)) return; } //BTS /r r/m16,r16
void CPU80386_OP0FAB_32() {modrm_generateInstructionTEXT("BTS",32,0,PARAM_MODRM_01); if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; modrm_addoffset = (int_32)((unsigned2signed32(instructionbufferd)>>5)<<2); if (unlikely(CPU[activeCPU].modrmstep==2)) { if (modrm_check32(&params,MODRM_src0,0|0x40)) return; if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; } if (CPU80386_instructionstepreadmodrmdw(2,&instructionbufferd2,MODRM_src0)) return; if (CPU[activeCPU].instructionstep==0) { CPU80386_BTS32(&instructionbufferd2,instructionbufferd); ++CPU[activeCPU].instructionstep; if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; } } if (CPU80386_instructionstepwritemodrmdw(4,instructionbufferd2,MODRM_src0)) return; } //BTS /r r/m32,r32

void CPU80386_OP0FB3_16() {modrm_generateInstructionTEXT("BTR",16,0,PARAM_MODRM_01); if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; modrm_addoffset = (int_32)((unsigned2signed16(instructionbufferw)>>4)<<1); if (unlikely(CPU[activeCPU].modrmstep==2)) { if (modrm_check16(&params,MODRM_src0,0|0x40)) return; if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmw(2,&instructionbufferw2,MODRM_src0)) return; if (CPU[activeCPU].instructionstep==0) { CPU80386_BTR16(&instructionbufferw2,instructionbufferw); ++CPU[activeCPU].instructionstep; if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; } } if (CPU8086_instructionstepwritemodrmw(4,instructionbufferw2,MODRM_src0,0)) return;} //BTR /r r/m16,r16
void CPU80386_OP0FB3_32() {modrm_generateInstructionTEXT("BTR",32,0,PARAM_MODRM_01); if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; modrm_addoffset = (int_32)((unsigned2signed32(instructionbufferd)>>5)<<2); if (unlikely(CPU[activeCPU].modrmstep==2)) { if (modrm_check32(&params,MODRM_src0,0|0x40)) return; if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; } if (CPU80386_instructionstepreadmodrmdw(2,&instructionbufferd2,MODRM_src0)) return; if (CPU[activeCPU].instructionstep==0) { CPU80386_BTR32(&instructionbufferd2,instructionbufferd); ++CPU[activeCPU].instructionstep; if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; } } if (CPU80386_instructionstepwritemodrmdw(4,instructionbufferd2,MODRM_src0)) return; } //BTR /r r/m32,r32

void CPU80386_OP0FBA_16() {
	//memcpy(&info,&params.info[MODRM_src0],sizeof(info)); //Store the address for debugging!
	memcpy(&info,&params.info[MODRM_src0],sizeof(info)); //Store the address for debugging!
	switch (thereg)
	{
		case 4: //BT r/m16,imm8
			//Debugger
			if (unlikely(cpudebugger))
			{
				cleardata(&modrm_param1[0],sizeof(modrm_param1));
				modrm_text16(&params,MODRM_src0,&modrm_param1[0]);
				debugger_setcommand("BT %s,%02X",modrm_param1,immb); //Log the command!
			}
			//Actual execution!
			modrm_addoffset = (int_32)((unsigned2signed8(immb)>>4)<<1);
			if (unlikely(CPU[activeCPU].modrmstep == 0)) { if (modrm_check16(&params, MODRM_src0, 1|0x40)) return; if (modrm_check16(&params, MODRM_src0, 1|0xA0)) return; }
			if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src0)) return;
			CPU80386_BT16(instructionbufferw,immb);
			break;
		case 5: //BTS r/m16,imm8
			if (unlikely(cpudebugger))
			{
				cleardata(&modrm_param1[0],sizeof(modrm_param1));
				modrm_text16(&params,MODRM_src0,&modrm_param1[0]);
				debugger_setcommand("BTS %s,%02X",modrm_param1,immb); //Log the command!
			}
			//Actual execution!
			modrm_addoffset = (int_32)((unsigned2signed8(immb)>>4)<<1);
			if (unlikely(CPU[activeCPU].modrmstep==0))
			{
				if (modrm_check16(&params,MODRM_src0,0|0x40)) return;
				if (modrm_check16(&params,MODRM_src0,0|0xA0)) return;
			}
			if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src0)) return;
			if (CPU[activeCPU].instructionstep==0)
			{
				CPU80386_BTS16(&instructionbufferw,immb);
				++CPU[activeCPU].instructionstep;
				if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; }
			}
			if (CPU8086_instructionstepwritemodrmw(2,instructionbufferw,MODRM_src0,0)) return;
			break;
		case 6: //BTR r/m16,imm8
			if (unlikely(cpudebugger))
			{
				cleardata(&modrm_param1[0],sizeof(modrm_param1));
				modrm_text16(&params,MODRM_src0,&modrm_param1[0]);
				debugger_setcommand("BTR %s,%02X",modrm_param1,immb); //Log the command!
			}
			//Actual execution!
			modrm_addoffset = (int_32)((unsigned2signed8(immb)>>4)<<1);
			if (unlikely(CPU[activeCPU].modrmstep==0))
			{
				if (modrm_check16(&params,MODRM_src0,0|0x40)) return;
				if (modrm_check16(&params,MODRM_src0,0|0xA0)) return;
			}
			if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src0)) return;
			if (CPU[activeCPU].instructionstep==0)
			{
				CPU80386_BTR16(&instructionbufferw,immb);
				++CPU[activeCPU].instructionstep;
				if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; }
			}
			if (CPU8086_instructionstepwritemodrmw(2,instructionbufferw,MODRM_src0,0)) return;
			break;
		case 7: //BTC r/m16,imm8
			if (unlikely(cpudebugger))
			{
				cleardata(&modrm_param1[0],sizeof(modrm_param1));
				modrm_text16(&params,MODRM_src0,&modrm_param1[0]);
				debugger_setcommand("BTC %s,%02X",modrm_param1,immb); //Log the command!
			}
			//Actual execution!
			modrm_addoffset = (int_32)((unsigned2signed8(immb)>>4)<<1);
			if (unlikely(CPU[activeCPU].modrmstep==0))
			{
				if (modrm_check16(&params,MODRM_src0,0|0x40)) return;
				if (modrm_check16(&params,MODRM_src0,0|0xA0)) return;
			}
			if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src0)) return;
			if (CPU[activeCPU].instructionstep==0)
			{
				CPU80386_BTC16(&instructionbufferw,immb);
				++CPU[activeCPU].instructionstep;
				if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; }
			}
			if (CPU8086_instructionstepwritemodrmw(2,instructionbufferw,MODRM_src0,0)) return;
			break;
		default: //Unknown instruction?
			unkOP0F_386(); //Unknown instruction!
			break;
	}
}

void CPU80386_OP0FBA_32() {
	//memcpy(&info,&params.info[MODRM_src0],sizeof(info)); //Store the address for debugging!
	memcpy(&info,&params.info[MODRM_src0],sizeof(info)); //Store the address for debugging!
	switch (thereg)
	{
		case 4: //BT r/m32,imm8
			//Debugger
			if (unlikely(cpudebugger))
			{
				cleardata(&modrm_param1[0],sizeof(modrm_param1));
				modrm_text32(&params,MODRM_src0,&modrm_param1[0]);
				debugger_setcommand("BT %s,%02X",modrm_param1,immb); //Log the command!
			}
			//Actual execution!
			modrm_addoffset = (int_32)((unsigned2signed8(immb)>>5)<<2);
			if (unlikely(CPU[activeCPU].modrmstep == 0)) { if (modrm_check32(&params, MODRM_src0, 1|0x40)) return; if (modrm_check32(&params, MODRM_src0, 1|0xA0)) return; }
			if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src0)) return;
			CPU80386_BT32(instructionbufferd,immb);
			break;
		case 5: //BTS r/m32,imm8
			if (unlikely(cpudebugger))
			{
				cleardata(&modrm_param1[0],sizeof(modrm_param1));
				modrm_text32(&params,MODRM_src0,&modrm_param1[0]);
				debugger_setcommand("BTS %s,%02X",modrm_param1,immb); //Log the command!
			}
			//Actual execution!
			modrm_addoffset = (int_32)((unsigned2signed8(immb)>>5)<<2);
			if (unlikely(CPU[activeCPU].modrmstep==0))
			{
				if (modrm_check32(&params,MODRM_src0,0|0x40)) return;
				if (modrm_check32(&params,MODRM_src0,0|0xA0)) return;
			}
			if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src0)) return;
			if (CPU[activeCPU].instructionstep==0)
			{
				CPU80386_BTS32(&instructionbufferd,immb);
				++CPU[activeCPU].instructionstep;
				if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; }
			}
			if (CPU80386_instructionstepwritemodrmdw(2,instructionbufferd,MODRM_src0)) return;
			break;
		case 6: //BTR r/m32,imm8
			if (unlikely(cpudebugger))
			{
				cleardata(&modrm_param1[0],sizeof(modrm_param1));
				modrm_text32(&params,MODRM_src0,&modrm_param1[0]);
				debugger_setcommand("BTR %s,%02X",modrm_param1,immb); //Log the command!
			}
			//Actual execution!
			modrm_addoffset = (int_32)((unsigned2signed8(immb)>>5)<<2);
			if (unlikely(CPU[activeCPU].modrmstep==0))
			{
				if (modrm_check32(&params,MODRM_src0,0|0x40)) return;
				if (modrm_check32(&params,MODRM_src0,0|0xA0)) return;
			}
			if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src0)) return;
			if (CPU[activeCPU].instructionstep==0)
			{
				CPU80386_BTR32(&instructionbufferd,immb);
				++CPU[activeCPU].instructionstep;
				if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; }
			}
			if (CPU80386_instructionstepwritemodrmdw(2,instructionbufferd,MODRM_src0)) return;
			break;
		case 7: //BTC r/m32,imm8
			if (unlikely(cpudebugger))
			{
				cleardata(&modrm_param1[0],sizeof(modrm_param1));
				modrm_text32(&params,MODRM_src0,&modrm_param1[0]);
				debugger_setcommand("BTC %s,%02X",modrm_param1,immb); //Log the command!
			}
			//Actual execution!
			modrm_addoffset = (int_32)((unsigned2signed8(immb)>>5)<<2);
			if (unlikely(CPU[activeCPU].modrmstep==0))
			{
				if (modrm_check32(&params,MODRM_src0,0|0x40)) return;
				if (modrm_check32(&params,MODRM_src0,0|0xA0)) return;
			}
			if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src0)) return;
			if (CPU[activeCPU].instructionstep==0)
			{
				CPU80386_BTC32(&instructionbufferd,immb);
				++CPU[activeCPU].instructionstep;
				if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; }
			}
			if (CPU80386_instructionstepwritemodrmdw(2,instructionbufferd,MODRM_src0)) return;
			break;
		default: //Unknown instruction?
			unkOP0F_386(); //Unknown instruction!
			break;
	}
}

void CPU80386_OP0FBB_16() {modrm_generateInstructionTEXT("BTC",16,0,PARAM_MODRM12); if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; modrm_addoffset = (int_32)((unsigned2signed16(instructionbufferw)>>4)<<1); if (unlikely(CPU[activeCPU].modrmstep==2)) { if (modrm_check16(&params,MODRM_src0,0|0x40)) return; if (modrm_check16(&params,MODRM_src0,0|0xA0)) return; } if (CPU8086_instructionstepreadmodrmw(2,&instructionbufferw2,MODRM_src0)) return; if (CPU[activeCPU].instructionstep==0) { CPU80386_BTC16(&instructionbufferw2,instructionbufferw); ++CPU[activeCPU].instructionstep; if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; } } if (CPU8086_instructionstepwritemodrmw(4,instructionbufferw2,MODRM_src0,0)) return; } //BTC /r r/m16,r16
void CPU80386_OP0FBB_32() {modrm_generateInstructionTEXT("BTC",32,0,PARAM_MODRM12); if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; modrm_addoffset = (int_32)((unsigned2signed32(instructionbufferd)>>5)<<2); if (unlikely(CPU[activeCPU].modrmstep==2)) { if (modrm_check32(&params,MODRM_src0,0|0x40)) return; if (modrm_check32(&params,MODRM_src0,0|0xA0)) return; } if (CPU80386_instructionstepreadmodrmdw(2,&instructionbufferd2,MODRM_src0)) return; if (CPU[activeCPU].instructionstep==0) { CPU80386_BTC32(&instructionbufferd2,instructionbufferd); ++CPU[activeCPU].instructionstep; if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; } } if (CPU80386_instructionstepwritemodrmdw(4,instructionbufferd2,MODRM_src0)) return; } //BTC /r r/m32,r32

//Bit scan instructions

void CPU80386_OP0FBC_16() {
	word temp;
	modrm_generateInstructionTEXT("BSF",16,0,PARAM_MODRM12);
	if (unlikely(CPU[activeCPU].modrmstep==0))
	{
		if (modrm_check16(&params,MODRM_src1,1|0x40)) return;
		if (modrm_check16(&params,MODRM_src0,0|0x40)) return;
		if (modrm_check16(&params,MODRM_src1,1|0xA0)) return;
		if (modrm_check16(&params,MODRM_src0,0|0xA0)) return;
	}
	if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; //Read src!
	if (instructionbufferw==0) //Nothing?
	{
		FLAGW_ZF(1); //Set zero flag!
		BST_cnt = 0; //No count!
		CPU_apply286cycles(); /* Apply cycles */
	}
	else
	{
		if (CPU8086_instructionstepreadmodrmw(2,&instructionbufferw2,MODRM_src0)) return; //Read dest!
		if (CPU[activeCPU].instructionstep==0) //Executing?
		{
			temp = 0;
			BST_cnt = 0; //Init counter!
			instructionbufferw2 = 0; //Init to the first result, which doesn't enter the following loop!
			for (;(((instructionbufferw>>temp)&1)==0) && (temp<16);) //Still searching?
			{
				++temp;
				instructionbufferw2 = temp;
				++BST_cnt; //Increase counter!
			}
			flag_log16(instructionbufferw2);
			FLAGW_ZF(0);
			++BST_cnt; //Increase counter!
			++CPU[activeCPU].instructionstep;
			CPU_apply286cycles(); /* Apply cycles */
			if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; } //Delay when running!
		}
		if (CPU8086_instructionstepwritemodrmw(4,instructionbufferw2,MODRM_src0,0)) return; //Write the result!
	}
} //BSF /r r16,r/m16
void CPU80386_OP0FBC_32() {
	uint_32 temp;
	modrm_generateInstructionTEXT("BSF",32,0,PARAM_MODRM12);
	if (unlikely(CPU[activeCPU].modrmstep==0))
	{
		if (modrm_check32(&params,MODRM_src1,1|0x40)) return;
		if (modrm_check32(&params,MODRM_src0,0|0x40)) return;
		if (modrm_check32(&params,MODRM_src1,1|0xA0)) return;
		if (modrm_check32(&params,MODRM_src0,0|0xA0)) return;
	}
	if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; //Read src!
	if (instructionbufferd==0) //Nothing?
	{
		FLAGW_ZF(1); //Set zero flag!
		BST_cnt = 0; //No count!
		CPU_apply286cycles(); /* Apply cycles */
	}
	else
	{
		if (CPU80386_instructionstepreadmodrmdw(2,&instructionbufferd2,MODRM_src0)) return; //Read dest!
		if (CPU[activeCPU].instructionstep==0) //Executing?
		{
			temp = 0;
			BST_cnt = 0; //Init counter!
			instructionbufferd2 = 0; //Init to the first result, which doesn't enter the following loop!
			for (;(((instructionbufferd>>temp)&1)==0) && (temp<32);) //Still searching?
			{
				++temp;
				instructionbufferd2 = temp;
				++BST_cnt; //Increase counter!
			}
			flag_log32(instructionbufferd2);
			FLAGW_ZF(0);
			++BST_cnt; //Increase counter!
			++CPU[activeCPU].instructionstep;
			CPU_apply286cycles(); /* Apply cycles */
			if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; } //Delay when running!
		}
		if (CPU80386_instructionstepwritemodrmdw(4,instructionbufferd2,MODRM_src0)) return; //Write the result!
	}
} //BSF /r r32,r/m32

void CPU80386_OP0FBD_16() {
	word temp;
	modrm_generateInstructionTEXT("BSR",16,0,PARAM_MODRM12);
	if (unlikely(CPU[activeCPU].modrmstep==0))
	{
		if (modrm_check16(&params,MODRM_src1,1|0x40)) return;
		if (modrm_check16(&params,MODRM_src0,0|0x40)) return;
		if (modrm_check16(&params,MODRM_src1,1|0xA0)) return;
		if (modrm_check16(&params,MODRM_src0,0|0xA0)) return;
	}
	if (CPU8086_instructionstepreadmodrmw(0,&instructionbufferw,MODRM_src1)) return; //Read src!
	if (instructionbufferw==0) //Nothing?
	{
		FLAGW_ZF(1); //Set zero flag!
		BST_cnt = 0; //No count!
		CPU_apply286cycles(); /* Apply cycles */
	}
	else
	{
		if (CPU8086_instructionstepreadmodrmw(2,&instructionbufferw2,MODRM_src0)) return; //Read dest!
		if (CPU[activeCPU].instructionstep==0) //Executing?
		{
			temp = 15;
			BST_cnt = 0;
			instructionbufferw2 = temp; //Save the current value!
			for (;(((instructionbufferw>>temp)&1)==0) && (temp!=0xFFFF);) //Still searching?
			{
				--temp;
				instructionbufferw2 = temp;
			}
			flag_log16(instructionbufferw2);
			FLAGW_ZF(0);
			++CPU[activeCPU].instructionstep;
			CPU_apply286cycles(); /* Apply cycles */
			if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; } //Delay when running!
		}
		if (CPU8086_instructionstepwritemodrmw(4,instructionbufferw2,MODRM_src0,0)) return; //Write the result!
	}
} //BSR /r r16,r/m16
void CPU80386_OP0FBD_32() {
	uint_32 temp;
	modrm_generateInstructionTEXT("BSR",32,0,PARAM_MODRM12);
	if (unlikely(CPU[activeCPU].modrmstep==0))
	{
		if (modrm_check32(&params,MODRM_src1,1|0x40)) return;
		if (modrm_check32(&params,MODRM_src0,0|0x40)) return;
		if (modrm_check32(&params,MODRM_src1,1|0xA0)) return;
		if (modrm_check32(&params,MODRM_src0,0|0xA0)) return;
	}
	if (CPU80386_instructionstepreadmodrmdw(0,&instructionbufferd,MODRM_src1)) return; //Read src!
	if (instructionbufferd==0) //Nothing?
	{
		FLAGW_ZF(1); //Set zero flag!
		BST_cnt = 0; //No count!
		CPU_apply286cycles(); /* Apply cycles */
	}
	else
	{
		if (CPU80386_instructionstepreadmodrmdw(2,&instructionbufferd2,MODRM_src0)) return; //Read dest!
		if (CPU[activeCPU].instructionstep==0) //Executing?
		{
			temp = 31;
			BST_cnt = 0;
			instructionbufferd2 = temp; //Save the current value!
			for (;(((instructionbufferd>>temp)&1)==0) && (temp!=0xFFFFFFFF);) //Still searching?
			{
				--temp;
				instructionbufferd2 = temp;
			}
			flag_log32(instructionbufferd2);
			FLAGW_ZF(0);
			++CPU[activeCPU].instructionstep;
			CPU_apply286cycles(); /* Apply cycles */
			if (modrm_ismemory(params)) {CPU[activeCPU].executed = 0; return; } //Delay when running!
		}
		if (CPU80386_instructionstepwritemodrmdw(4,instructionbufferd2,MODRM_src0)) return; //Write the result!
	}
} //BSR /r r32,r/m32
