#include "headers/cpu/mmu.h" //Ourselves!
#include "headers/cpu/cpu.h"
#include "headers/cpu/memory_adressing.h" //Memory assist functions!
#include "headers/cpu/paging.h" //Paging functions!
#include "headers/support/log.h" //Logging support!
#include "headers/cpu/protection.h" //Protection support!
#include "headers/cpu/paging.h" //Protection support!
#include "headers/emu/debugger/debugger.h" //Debugger support for logging MMU accesses!
#include "headers/hardware/xtexpansionunit.h" //XT expansion unit support!
#include "headers/mmu/mmu_internals.h" //Internal MMU call support!
#include "headers/mmu/mmuhandler.h" //MMU direct handler support!
#include "headers/cpu/protecteddebugging.h" //Protected mode debugging support!
#include "headers/cpu/biu.h" //BIU support!

extern MMU_type MMU; //MMU itself!

//Are we disabled?
#define __HW_DISABLED 0

#define CPU286_WAITSTATE_DELAY 1

byte writeword = 0; //Hi-end word written?

//Pointer support (real mode only)!
void *MMU_directptr(uint_32 address, uint_32 size) //Full ptr to real MMU memory!
{
	if ((address <= MMU.size) && ((address + size) <= MMU.size)) //Within our limits of flat memory and not paged?
	{
		return &MMU.memory[address]; //Give the memory's start!
	}

	//Don't signal invalid memory address: we're internal emulator call!
	return NULL; //Not found!	
}

//MMU_ptr: 80(1)86 only!
void *MMU_ptr(sword segdesc, word segment, uint_32 offset, byte forreading, uint_32 size) //Gives direct memory pointer!
{
	uint_32 realaddr;
	if (MMU.memory == NULL) //None?
	{
		return NULL; //NULL: no memory alligned!
	}

	if (EMULATED_CPU <= CPU_NECV30) //-NEC V20/V30 wraps offset arround?
	{
		offset &= 0xFFFF; //Wrap arround!
	}
	else
	{
		return NULL; //80286+ isn't supported here!
	}
	realaddr = (segment << 4) + offset; //Our real address!
	realaddr = BITOFF(realaddr, 0x100000); //Wrap arround, disable A20!	
	return MMU_directptr(realaddr, size); //Direct pointer!
}

extern byte is_XT; //Are we an XT?
extern byte is_Compaq; //Are we emulating a Compaq architecture?

//Address translation routine.
uint_32 MMU_realaddr(sword segdesc, word segment, uint_32 offset, byte wordop, byte is_offset16) //Real adress?
{
	SEGMENT_DESCRIPTOR *descriptor; //For checking Expand-down data descriptors!
	INLINEREGISTER uint_32 realaddress;
	//word originalsegment = segment;
	//uint_32 originaloffset = offset; //Save!
	realaddress = offset; //Load the address!
	if ((EMULATED_CPU==CPU_8086) || (EMULATED_CPU==CPU_NECV30 && !((realaddress==0x10000) && wordop))) //-NEC V20/V30 wraps offset arround 64kB? NEC V20/V30 allows 1 byte more in word operations!
	{
		realaddress &= 0xFFFF; //Wrap arround!
	}
	writeword = 0; //Reset word-write flag for checking next bytes!

	if (likely(segdesc!=-1)) //valid segment descriptor?
	{
		descriptor = &CPU[activeCPU].SEG_DESCRIPTOR[segdesc]; //Get our using descriptor!
		if (unlikely((GENERALSEGMENTPTR_S(descriptor) == 1) && (EXECSEGMENTPTR_ISEXEC(descriptor) == 0) && DATASEGMENTPTR_E(descriptor))) //Data segment that's expand-down?
		{
			if (is_offset16) //16-bits offset? Set the high bits for compatibility!
			{
				realaddress |= 0xFFFF0000; //Convert to 32-bits for adding correctly!
			}
		}
	}
	realaddress += CPU_MMU_start(segdesc, segment);

	if (is_XT && (EMULATED_CPU<CPU_80286)) realaddress &= 0xFFFFF; //Only 20-bits address is available on a XT without newer CPU!
	else if (EMULATED_CPU==CPU_80286) realaddress &= 0xFFFFFF; //Only 24-bits is available on a AT!

	//We work!
	//dolog("MMU","\nAddress translation: %04X:%08X=%08X",originalsegment,originaloffset,realaddress); //Log the converted address!
	return realaddress; //Give real adress!
}

uint_32 BUSdatalatch=0;

void processBUS(uint_32 address, byte index, byte data)
{
	uint_32 masks[4] = {0xFF,0xFF00,0xFF0000,0xFF000000};
	BUSdatalatch &= ~masks[index&3]; //Clear the bits!
	BUSdatalatch |= (data<<((index&3)<<3)); //Set the bits on the BUS!
	latchBUS(address,BUSdatalatch); //This address is to be latched!
}

//OPcodes for the debugger!
byte OPbuffer[256]; //A large opcode buffer!
word OPlength = 0; //The length of the opcode buffer!

extern byte cpudebugger; //To debug the CPU?

void MMU_addOP(byte data)
{
	if (OPlength < sizeof(OPbuffer)) //Not finished yet?
	{
		OPbuffer[OPlength++] = data; //Save a part of the opcode!
	}
}

void MMU_clearOP()
{
	OPlength = 0; //Clear the buffer!
}

//CPU/EMU simple memory access routine.
extern uint_32 wordaddress; //Word address used during memory access!

byte checkDirectMMUaccess(uint_32 realaddress, byte readflags, byte CPL)
{
	//Check for Page Faults!
	if (is_paging()) //Are we paging?
	{
		if (CPU_Paging_checkPage(realaddress,readflags,CPL)) //Map it using the paging mechanism! Errored out?
		{
			return 1; //Error out!
		}
	}
	return 0; //OK!	
}

//readflags = 1|(opcode<<1) for reads! 0 for writes!
byte checkMMUaccess(sword segdesc, word segment, uint_32 offset, byte readflags, byte CPL, byte is_offset16, byte subbyte) //Check if a byte address is invalid to read/write for a purpose! Used in all CPU modes! Subbyte is used for alignment checking!
{
	INLINEREGISTER uint_32 realaddress;
	if (EMULATED_CPU<=CPU_NECV30) return 0; //No checks are done in the old processors!

	if (FLAGREGR_AC(CPU[activeCPU].registers) && (offset&7) && (subbyte==0x20) && (segdesc!=-1)) //Aligment enforced and wrong? Don't apply on internal accesses!
	{
		CPU_AC(0); //Alignment DWORD check fault!
		return 1; //Error out!
	}
	if (FLAGREGR_AC(CPU[activeCPU].registers) && (offset&3) && (subbyte==0x10) && (segdesc!=-1)) //Aligment enforced and wrong? Don't apply on internal accesses!
	{
		CPU_AC(0); //Alignment DWORD check fault!
		return 1; //Error out!
	}
	if (FLAGREGR_AC(CPU[activeCPU].registers) && (offset&1) && (subbyte==0x8) && (segdesc!=-1)) //Aligment enforced and wrong? Don't apply on internal accesses!
	{
		CPU_AC(0); //Alignment WORD check fault!
		return 1; //Error out!
	}

	if (CPU_MMU_checklimit(segdesc,segment,offset,readflags,is_offset16)) //Disallowed?
	{
		MMU.invaddr = 2; //Invalid address signaling!
		return 1; //Not found.
	}

	//Check for paging and debugging next!
	realaddress = MMU_realaddr(segdesc, segment, offset, 0,is_offset16); //Real adress!

	switch (readflags) //What kind of flags?
	{
		case 0: //Data Write?
			if (unlikely(checkProtectedModeDebugger(realaddress,PROTECTEDMODEDEBUGGER_TYPE_DATAWRITE))) return 1; //Error out!
			break;
		case 1: //Data Read?
			if (unlikely(checkProtectedModeDebugger(realaddress,PROTECTEDMODEDEBUGGER_TYPE_DATAREAD))) return 1; //Error out!
			break;
		case 3: //Opcode read?
			if (unlikely(checkProtectedModeDebugger(realaddress,PROTECTEDMODEDEBUGGER_TYPE_EXECUTION))) return 1; //Error out!
			break;
		case 2: //Unknown?
		default: //Unknown? Unsupported!
			break;
	}

	if (checkDirectMMUaccess(realaddress,readflags,CPL)) //Failure in the Paging Unit?
	{
		return 1; //Error out!
	}

	//We're valid?
	return 0; //We're a valid access for both MMU and Paging! Allow this instruction to execute!
}

extern byte MMU_logging; //Are we logging?

byte Paging_directrb(sword segdesc, uint_32 realaddress, byte writewordbackup, byte opcode, byte index)
{
	byte result;
	if (is_paging()) //Are we paging?
	{
		realaddress = mappage(realaddress,0,getCPL()); //Map it using the paging mechanism!
	}

	if (segdesc!=-1) //Normal memory access by the CPU itself?
	{
		if (writewordbackup==0) //First data of the (d)word access?
		{
			wordaddress = realaddress; //Word address used during memory access!
		}
	}

	if (is_Compaq!=1) //Non-Compaq has normal wraparround?
	{
		realaddress &= MMU.wraparround; //Apply A20!
	}
	else //Compaq: Only 1MB-2MB range is converted to 0MB-1MB range!
	{
		if (MMU.A20LineEnabled==0) //Wrap enabled? It's for the 1MB-2MB range only!
		{
			if ((realaddress&~0xFFFFF)==0x100000) //Are we in the 1MB-2MB range?
			{
				realaddress &= MMU.wraparround; //Apply A20!
			}
		}
	}

	//Normal memory access!
	result = MMU_INTERNAL_directrb_realaddr(realaddress,index); //Read from MMU/hardware!

	if (MMU_logging) //To log?
	{
		debugger_logmemoryaccess(0,realaddress,result,LOGMEMORYACCESS_PAGED); //Log it!
	}

	return result; //Give the result!
}

void Paging_directwb(sword segdesc, uint_32 realaddress, byte val, byte index, byte is_offset16, byte writewordbackup)
{
	if (is_paging()) //Are we paging?
	{
		realaddress = mappage(realaddress,1,getCPL()); //Map it using the paging mechanism!
	}

	if (segdesc!=-1) //Normal memory access?
	{
		if (writewordbackup==0) //First data of the word access?
		{
			wordaddress = realaddress; //Word address used during memory access!
		}
	}

	if (MMU_logging) //To log?
	{
		debugger_logmemoryaccess(1,realaddress,val,LOGMEMORYACCESS_PAGED); //Log it!
	}

	if (is_Compaq!=1) //Non-Compaq has normal wraparround?
	{
		realaddress &= MMU.wraparround; //Apply A20!
	}
	else //Compaq: Only 1MB-2MB range is converted to 0MB-1MB range!
	{
		if (MMU.A20LineEnabled==0) //Wrap enabled? It's for the 1MB-2MB range only!
		{
			if ((realaddress&~0xFFFFF)==0x100000) //Are we in the 1MB-2MB range?
			{
				realaddress &= MMU.wraparround; //Apply A20!
			}
		}
	}

	//Normal memory access!
	MMU_INTERNAL_directwb_realaddr(realaddress,val,index); //Set data!
}

void MMU_generateaddress(sword segdesc, word segment, uint_32 offset, byte opcode, byte index, byte is_offset16) //Get adress, opcode=1 when opcode reading, else 0!
{
	INLINEREGISTER uint_32 realaddress;
	byte writewordbackup = writeword; //Save the old value first!
	if (MMU.memory==NULL) //No mem?
	{
		//dolog("MMU","R:No memory present!");
		MMU.invaddr = 1; //Invalid adress!
		return; //Out of bounds!
	}

	realaddress = MMU_realaddr(segdesc, segment, offset, writeword, is_offset16); //Real adress!

	if (is_paging()) //Are we paging?
	{
		realaddress = mappage(realaddress,(opcode==0),getCPL()); //Map it using the paging mechanism!
	}
	writeword = writewordbackup; //Restore the word address backup!
}

OPTINLINE byte MMU_INTERNAL_rb(sword segdesc, word segment, uint_32 offset, byte opcode, byte index, byte is_offset16) //Get adress, opcode=1 when opcode reading, else 0!
{
	INLINEREGISTER byte result; //The result!
	INLINEREGISTER uint_32 realaddress;
	byte writewordbackup = writeword; //Save the old value first!
	if (MMU.memory==NULL) //No mem?
	{
		//dolog("MMU","R:No memory present!");
		MMU.invaddr = 1; //Invalid adress!
		return 0xFF; //Out of bounds!
	}

	realaddress = MMU_realaddr(segdesc, segment, offset, writeword, is_offset16); //Real adress!

	result = Paging_directrb(segdesc,realaddress,writewordbackup,opcode,index); //Read through the paging unit and hardware layer!
	processBUS(realaddress, index, result); //Process us on the BUS!

	if (unlikely(MMU_logging)) //To log?
	{
		debugger_logmemoryaccess(0,realaddress,result,LOGMEMORYACCESS_NORMAL); //Log it!
	}

	return result; //Give the result!
}

OPTINLINE byte MMU_BIU_INTERNAL_rw(sword segdesc, word segment, uint_32 offset, byte opcode, byte index, byte is_offset16) //Get adress, opcode=1 when opcode reading, else 0!
{
	INLINEREGISTER byte result; //The result!
	INLINEREGISTER uint_32 realaddress;
	byte writewordbackup = writeword; //Save the old value first!
	if (MMU.memory==NULL) //No mem?
	{
		//dolog("MMU","R:No memory present!");
		MMU.invaddr = 1; //Invalid adress!
		return 0xFF; //Out of bounds!
	}

	realaddress = MMU_realaddr(segdesc, segment, offset, writeword, is_offset16); //Real adress!

	result = Paging_directrb(segdesc,realaddress,writewordbackup,opcode,index); //Read through the paging unit and hardware layer!
	processBUS(realaddress, index, result); //Process us on the BUS!
	return result; //Give the result!
}

OPTINLINE word MMU_INTERNAL_rw(sword segdesc, word segment, uint_32 offset, byte opcode, byte index, byte is_offset16) //Get adress!
{
	INLINEREGISTER word result;
	result = MMU_INTERNAL_rb(segdesc, segment, offset, opcode,index|0x40,is_offset16); //We're accessing a word!
	result |= (MMU_INTERNAL_rb(segdesc, segment, offset + 1, opcode,index|1|0x40,is_offset16) << 8); //Get adress word!
	return result; //Give the result!
}

OPTINLINE uint_32 MMU_INTERNAL_rdw(sword segdesc, word segment, uint_32 offset, byte opcode, byte index, byte is_offset16) //Get adress!
{
	INLINEREGISTER uint_32 result;
	result = MMU_INTERNAL_rw(segdesc, segment, offset, opcode,index|0x80,is_offset16);
	result |= (MMU_INTERNAL_rw(segdesc, segment, offset + 2, opcode,(index|2|0x80),is_offset16) << 16); //Get adress dword!
	return result; //Give the result!
}

extern byte EMU_RUNNING; //Emulator is running?

OPTINLINE void MMU_INTERNAL_wb(sword segdesc, word segment, uint_32 offset, byte val, byte index, byte is_offset16) //Set adress!
{
	INLINEREGISTER uint_32 realaddress;
	byte writewordbackup = writeword; //Save the old value first!
	if (MMU.invaddr) return; //Abort!
	if ((MMU.memory==NULL) || !MMU.size) //No mem?
	{
		//dolog("MMU","W:No memory present!");
		MMU.invaddr = 1; //Invalid address signaling!
		return; //Out of bounds!
	}
	
	/*if (LOG_MMU_WRITES) //Log MMU writes?
	{
		dolog("debugger","MMU: Write to %04X:%08X=%02X",segment,offset,val); //Log our written value!
	}*/

	realaddress = MMU_realaddr(segdesc, segment, offset, writeword, is_offset16); //Real adress!

	if (MMU_logging) //To log?
	{
		debugger_logmemoryaccess(1,realaddress,val,LOGMEMORYACCESS_NORMAL); //Log it!
	}

	processBUS(realaddress, index, val); //Process us on the BUS!
	Paging_directwb(segdesc,realaddress,val,index,is_offset16,writewordbackup); //Write through the paging unit and hardware layer!
}

OPTINLINE void MMU_INTERNAL_ww(sword segdesc, word segment, uint_32 offset, word val, byte index, byte is_offset16) //Set adress (word)!
{
	INLINEREGISTER word w;
	w = val;
	MMU_INTERNAL_wb(segdesc,segment,offset,w&0xFF,(index|0x40),is_offset16); //Low first!
	writeword = 1; //We're writing a 2nd byte word, for emulating the NEC V20/V30 0x10000 overflow bug.
	w >>= 8; //Shift low!
	MMU_INTERNAL_wb(segdesc,segment,offset+1,(byte)w,(index|1|0x40),is_offset16); //High last!
}

OPTINLINE void MMU_INTERNAL_wdw(sword segdesc, word segment, uint_32 offset, uint_32 val, byte index, byte is_offset16) //Set adress (dword)!
{
	INLINEREGISTER uint_32 d;
	d = val;
	MMU_INTERNAL_ww(segdesc,segment,offset,d&0xFFFF,(index|0x80),is_offset16); //Low first!
	d >>= 16; //Shift low!
	MMU_INTERNAL_ww(segdesc,segment,offset+2,d,(index|2|0x80),is_offset16); //High last!
}

//Routines used by CPU!
byte MMU_directrb_realaddr(uint_32 realaddress) //Read without segment/offset translation&protection (from system/interrupt)!
{
	return MMU_INTERNAL_directrb_realaddr(realaddress,0);
}
void MMU_directwb_realaddr(uint_32 realaddress, byte val) //Read without segment/offset translation&protection (from system/interrupt)!
{
	MMU_INTERNAL_directwb_realaddr(realaddress,val,0);
}

extern byte CPU_databussize; //0=16/32-bit bus! 1=8-bit bus when possible (8088/80188)!
void MMU_wb(sword segdesc, word segment, uint_32 offset, byte val, byte is_offset16) //Set adress!
{
	MMU_INTERNAL_wb(segdesc,segment,offset,val,0,is_offset16);
}
void MMU_ww(sword segdesc, word segment, uint_32 offset, word val, byte is_offset16) //Set adress!
{
	MMU_INTERNAL_ww(segdesc,segment,offset,val,0,is_offset16);
}
void MMU_wdw(sword segdesc, word segment, uint_32 offset, uint_32 val, byte is_offset16) //Set adress!
{
	MMU_INTERNAL_wdw(segdesc,segment,offset,val,0,is_offset16);
}
byte MMU_rb(sword segdesc, word segment, uint_32 offset, byte opcode, byte is_offset16) //Get adress, opcode=1 when opcode reading, else 0!
{
	return MMU_INTERNAL_rb(segdesc,segment,offset,opcode,0,is_offset16);
}
word MMU_rw(sword segdesc, word segment, uint_32 offset, byte opcode, byte is_offset16) //Get adress, opcode=1 when opcode reading, else 0!
{
	return MMU_INTERNAL_rw(segdesc,segment,offset,opcode,0,is_offset16);
}
uint_32 MMU_rdw(sword segdesc, word segment, uint_32 offset, byte opcode, byte is_offset16) //Get adress, opcode=1 when opcode reading, else 0!
{
	return MMU_INTERNAL_rdw(segdesc,segment,offset,opcode,0,is_offset16);
}

//Extra routines for the emulator.

//A20 bit enable/disable (80286+).
void MMU_setA20(byte where, byte enabled) //To enable A20?
{
	MMU.enableA20[where] = enabled?1:0; //Enabled?
	MMU.A20LineEnabled = (MMU.enableA20[0]|MMU.enableA20[1]); //Line enabled?
	MMU.wraparround = ((~0)^(((MMU.A20LineEnabled^1)&1)<<20)); //Clear A20 when both lines that specify it are disabled! Convert it to a simple mask to use!
}