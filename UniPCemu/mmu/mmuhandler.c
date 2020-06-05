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

#define IS_MMU
#include "headers/types.h" //Basic types!
#include "headers/cpu/mmu.h" //MMU support!
#include "headers/mmu/mmuhandler.h" //Our typedefs!
#include "headers/support/zalloc.h" //Memory allocation!
#include "headers/support/log.h" //Logging support!
#include "headers/support/fifobuffer.h" //Write buffer support!
#include "headers/emu/debugger/debugger.h" //Debugger support!
#include "headers/hardware/dram.h" //DRAM_access support!
#include "headers/emu/gpu/gpu.h" //Need GPU comp!
#include "headers/fopen64.h" //64-bit fopen support!
#include "headers/bios/biosrom.h" //BIOS/option ROM support!
#include "headers/hardware/vga/vga.h" //Video memory support!

extern BIOS_Settings_TYPE BIOS_Settings; //Settings!
extern MMU_type MMU; //MMU for direct access!

#define __HW_DISABLED 0

//What bits to take as a memory block to be translated and used(rounds memory down)?
#define MMU_BLOCKALIGNMENT 0xF

//Log invalid memory accesses?
//#define LOG_INVALID_MEMORY

//Log high memory access during special debugger?
//#define LOG_HIGH_MEMORY

//Now the core memory support!

byte MMU_logging = 0; //Are we logging?

byte MMU_ignorewrites = 0; //Ignore writes to the MMU from the CPU?

MMU_type MMU; //The MMU itself!

extern BIOS_Settings_TYPE BIOS_Settings; //The BIOS!

uint_32 user_memory_used = 0; //Memory used by the software!
byte force_memoryredetect = 0; //Force memory redetect?

byte bufferMMUwrites = 0; //To buffer MMU writes?
FIFOBUFFER *MMUBuffer = NULL; //MMU write buffer!
uint_32 mem_BUSValue = 0; //Last memory read/written, BUS value stored during reads/writes!
const uint_32 BUSmask[4] = { 0xFFFFFF00,0xFFFF00FF,0xFF00FFFF,0x00FFFFFF }; //Bus mask for easy toggling!
byte LOG_MMU_WRITES = 0; //Log MMU writes?
byte enableMMUbuffer = 0; //To buffer the MMU writes?

struct
{
MMU_WHANDLER writehandlers[100]; //Up to 100 write handlers!
uint_32 startoffsetw[100]; //Start offset of the handler!
uint_32 endoffsetw[100]; //End offset of the handler!
char modulew[100][20]; //Module names!
byte numw; //Ammount registered!

MMU_RHANDLER readhandlers[100]; //Up to 100 read handlers!
uint_32 startoffsetr[100]; //Start offset of the handler!
uint_32 endoffsetr[100]; //End offset of the handler!
char moduler[100][20]; //Module names!
byte numr; //Ammount registered!
} MMUHANDLER;

OPTINLINE void MMUHANDLER_countwrites()
{
	byte i,newentry;
	MMUHANDLER.numw=NUMITEMS(MMUHANDLER.writehandlers); //Init!
	for (;MMUHANDLER.numw;)
	{
		if (MMUHANDLER.writehandlers[MMUHANDLER.numw-1]) //Found?
		{
			break; //Stop searching!
		}
		--MMUHANDLER.numw; //Next!
	}

	//Now, compress the handlers to take the amount of items used!
	newentry = 0; //What entry to assign it to?
	//Now, compress the handlers into one straight list!
	for (i = 0; i < MMUHANDLER.numw; ++i) //Handle all handlers!
	{
		if (MMUHANDLER.writehandlers[i]) //Assigned?
		{
			MMUHANDLER.writehandlers[newentry] = MMUHANDLER.writehandlers[i]; //Handler itself!
			MMUHANDLER.startoffsetw[newentry] = MMUHANDLER.startoffsetw[i]; //Start offset!
			MMUHANDLER.endoffsetw[newentry] = MMUHANDLER.endoffsetw[i]; //End offset!
			memcpy(&MMUHANDLER.modulew[newentry], &MMUHANDLER.modulew[i], sizeof(MMUHANDLER.modulew[newentry])); //Module name!
			++newentry; //Entry has been assigned!
		}
	}
	MMUHANDLER.numw = newentry; //How many have been assigned!
	MMUHANDLER.writehandlers[newentry] = NULL; //Finish the list!
}

OPTINLINE void MMUHANDLER_countreads()
{
	byte i, newentry;
	MMUHANDLER.numr=NUMITEMS(MMUHANDLER.readhandlers); //Init!
	for (;MMUHANDLER.numr;)
	{
		if (MMUHANDLER.readhandlers[MMUHANDLER.numr-1]) //Found?
		{
			break; //Stop searching!
		}
		--MMUHANDLER.numr; //Next!
	}

	//Now, compress the handlers to take the amount of items used!
	newentry = 0; //What entry to assign it to?
	//Now, compress the handlers into one straight list!
	for (i = 0; i < MMUHANDLER.numr; ++i) //Handle all handlers!
	{
		if (MMUHANDLER.readhandlers[i]) //Assigned?
		{
			MMUHANDLER.readhandlers[newentry] = MMUHANDLER.readhandlers[i]; //Handler itself!
			MMUHANDLER.startoffsetr[newentry] = MMUHANDLER.startoffsetr[i]; //Start offset!
			MMUHANDLER.endoffsetr[newentry] = MMUHANDLER.endoffsetr[i]; //End offset!
			memcpy(&MMUHANDLER.moduler[newentry], &MMUHANDLER.moduler[i], sizeof(MMUHANDLER.moduler[newentry])); //Module name!
			++newentry; //Entry has been assigned!
		}
	}
	MMUHANDLER.numr = newentry; //How many have been assigned!
	MMUHANDLER.readhandlers[newentry] = NULL; //Finish the list!
}

void MMU_resetHandlers(char *module) //Initialise/reset handlers!
{
	char empty='\0'; //Empty string!
	byte i=0;
	if (!module) module=&empty; //Empty module patch!
	for(;i<NUMITEMS(MMUHANDLER.writehandlers);i++)
	{
		if ((strcmp(MMUHANDLER.modulew[i],module)==0) || (strcmp(module,"")==0)) //No module or current module?
		{
			MMUHANDLER.writehandlers[i] = NULL; //Reset!
			MMUHANDLER.startoffsetw[i] = 0; //Reset!
			MMUHANDLER.endoffsetw[i] = 0; //Reset!
		}

		if ((strcmp(MMUHANDLER.moduler[i],module)==0) || (strcmp(module,"")==0)) //No module or current module?
		{
			MMUHANDLER.readhandlers[i] = NULL; //Reset!
			MMUHANDLER.startoffsetr[i] = 0; //Reset!
			MMUHANDLER.endoffsetr[i] = 0; //Reset!
		}
	}

	if (!module) //All cleared?
	{
		MMUHANDLER.numw = 0; //Reset!
		MMUHANDLER.numr = 0; //Reset!
		MMUHANDLER.readhandlers[0] = NULL;
		MMUHANDLER.writehandlers[0] = NULL;
	}
	else //Cleared one module: search for the last one used!
	{
		MMUHANDLER_countwrites();
		MMUHANDLER_countreads();
	}
}

byte MMU_registerWriteHandler(MMU_WHANDLER handler, char *module) //Register a write handler!
{
	byte i=0;
	for (;i<NUMITEMS(MMUHANDLER.writehandlers);i++)
	{
		if (!MMUHANDLER.writehandlers[i]) //Not set?
		{
			MMUHANDLER.writehandlers[i] = handler; //Set the handler to use!
			memset(&MMUHANDLER.modulew[i],0,sizeof(MMUHANDLER.modulew[i])); //Init module!
			safestrcpy(MMUHANDLER.modulew[i],sizeof(MMUHANDLER.modulew[0]),module); //Set module!
			MMUHANDLER_countwrites(); //Recount!
			return 1; //Registered!
		}
	}
	return 0; //Error: ran out of space!
}

byte MMU_registerReadHandler(MMU_RHANDLER handler, char *module) //Register a read handler!
{
	byte i=0;
	for (;i<NUMITEMS(MMUHANDLER.readhandlers);i++)
	{
		if (!MMUHANDLER.readhandlers[i]) //Not set?
		{
			MMUHANDLER.readhandlers[i] = handler; //Set the handler to use!
			memset(&MMUHANDLER.moduler[i],0,sizeof(MMUHANDLER.moduler[i])); //Init module!
			safestrcpy(MMUHANDLER.moduler[i],sizeof(MMUHANDLER.moduler[0]),module); //Set module!
			MMUHANDLER_countreads(); //Recount!
			return 1; //Registered!
		}
	}
	return 0; //Error: ran out of space!
}

//Handler for special MMU-based I/O, direct addresses used!
OPTINLINE byte MMU_IO_writehandler(uint_32 offset, byte value)
{
	MMU_WHANDLER *list; //Current list item!
	MMU_WHANDLER current; //Current handler!
	if (unlikely(BIOS_writehandler(offset, value))) return 0; //BIOS responded!
	if (VGAmemIO_wb(offset, value)) return 0; //Video responded!
	current = *(list = &MMUHANDLER.writehandlers[0]); //Start of our list!
	if (likely(current == NULL)) return 1; //Finished?
	for (;;) //Search all available handlers!
	{
		if (unlikely(current(offset,value))) //Success?
		{
			return 0; //Abort searching: we're processed!
		}
		current = *(++list); //Next handler!
		if (likely(current == NULL)) break; //Finished?
	}
	return 1; //Normal memory access!
}

//Reading only!
uint_32 memory_dataaddr = 0; //The data address that's cached!
uint_32 memory_dataread = 0;
byte memory_datasize = 0; //The size of the data that has been read!
OPTINLINE byte MMU_IO_readhandler(uint_32 offset, byte index)
{
	byte dataread;
	MMU_RHANDLER *list; //Current list item!
	MMU_RHANDLER current; //Current handler!
	memory_datasize = 0; //Default to a size of invalid!
	memory_dataaddr = offset; //What address has been cached!
	if (BIOS_readhandler(offset,index)) return 0; //BIOS responded!
	if (VGAmemIO_rb(offset)) return 0; //Video responded!
	current = *(list = &MMUHANDLER.readhandlers[0]); //Start of our list!
	if (likely(current == NULL)) return 1; //Finished?
	for (;;) //Search all available handlers!
	{
		if (unlikely(current(offset,&dataread))) //Success reading?
		{
			memory_dataaddr = offset; //What address!
			memory_datasize = 1; //Only 1 byte!
			memory_dataread = dataread; //What has been read?
			return 0; //Abort searching: we're processed!
		}
		current = *(++list); //Next handler!
		if (likely(current == NULL)) break; //Finished?
	}
	return 1; //Normal memory access!
}

extern byte is_XT; //Are we emulating a XT architecture?
extern byte is_Compaq; //Are we emulating a Compaq architecture?

byte MoveLowMemoryHigh; //Disable HMA memory and enable the memory hole?

byte memoryprotect_FE0000 = 1; //Memory-protect block at FE0000?
byte BIOSROM_LowMemoryBecomesHighMemory = 0; //Disable low-memory mapping of the BIOS and OPTROMs! Disable mapping of low memory locations E0000-FFFFF used on the Compaq Deskpro 386.
extern byte BIOSROM_DisableLowMemory; //Disable low-memory mapping of the BIOS and OPTROMs! Disable mapping of low memory locations E0000-FFFFF used on the Compaq Deskpro 386.

byte MMU_memorymapinfo[0x10000]; //What memory hole is this? Low nibble=Block number of the memory! High nibble=Hole number
byte MMU_memorymaphole[0x2000]; //Memory hole identification. Bit set(for that 64KB memory aperture) means memory hole is present!
uint_32 MMU_memorymaplocpatch[0x100]; //Memory to substract for the mapped memory when mapped(4 entries used)!

//Memory hole start/end locations!
#define LOW_MEMORYHOLE_START 0xA0000
#define LOW_MEMORYHOLE_END 0x100000
#define MID_MEMORYHOLE_START 0xFA0000
#define MID_MEMORYHOLE_END 0x1000000
#define HIGH_MEMORYHOLE_START 0xC0000000
#define HIGH_MEMORYHOLE_END 0x100000000ULL

uint_32 MMU_calcmaplocpatch(byte memloc)
{
	uint_32 address;
	address = 0; //Default: don't substract!
	if ((MoveLowMemoryHigh&1) && (memloc)) //Move first block lower?
	{
		address += (LOW_MEMORYHOLE_END - LOW_MEMORYHOLE_START); //Patch into memory hole!
	}
	if ((MoveLowMemoryHigh&2) && (memloc>=2)) //Move second block lower?
	{
		address += (MID_MEMORYHOLE_END - MID_MEMORYHOLE_START); //Patch into memory hole!
	}
	if ((MoveLowMemoryHigh&4) && (memloc>=3)) //Move third block lower?
	{
		address += (uint_32)((uint_64)HIGH_MEMORYHOLE_END - (uint_64)HIGH_MEMORYHOLE_START); //Patch into memory hole!
	}
	return address; //How much to substract!
}

void MMU_precalcMemoryHoles()
{
	byte memloc, memoryhole;
	uint_32 address;
	uint_32 precalcpos;
	memset(&MMU_memorymaphole, 0, sizeof(MMU_memorymaphole)); //Init!
	for (address = 0, precalcpos = 0; precalcpos < 0x10000; ++precalcpos, address+=0x10000) //Map all memory blocks possible with 32-bit addresses!
	{
		memloc = 0; //Default: first memory block: low memory!
		memoryhole = 0; //Default: memory unavailable!
		if (address >= LOW_MEMORYHOLE_START) //Start of first hole?
		{
			if (unlikely(address < LOW_MEMORYHOLE_END)) //First hole?
			{
				memoryhole = 1; //First memory hole!
			}
			else //Mid memory?
			{
				memloc = 1; //Second memory block: mid memory!
				if (address >= MID_MEMORYHOLE_START) //Start of second hole?
				{
					if (unlikely(address < MID_MEMORYHOLE_END)) //Second hole?
					{
						memoryhole = 2; //Second memory hole!
					}
					else //High memory?
					{
						memloc = 2; //Third memory block!
						if (unlikely((address >= HIGH_MEMORYHOLE_START) && ((uint_64)address < (uint_64)HIGH_MEMORYHOLE_END))) //Start of third hole?
						{
							memoryhole = 3; //Third memory hole!
						}
						else
						{
							memloc = 3; //Fourth memory block!
						}
					}
				}
			}
		}
		if (memoryhole) //Is a memory hole?
		{
			MMU_memorymaphole[precalcpos >> 3] |= (1 << (precalcpos & 7)); //Set us up as a memory hole!
		}
		MMU_memorymapinfo[precalcpos] = ((memloc) | (memoryhole << 4)); //Save the block and hole number together!
	}
}

struct
{
	uint_32 maskedaddress; //Masked address to match!
	uint_32 memorylocpatch; //How much to substract for the physical memory location?
	uint_32 byteaddr; //Byte address within the block of memory(address MOD 8)!
	byte* cache; //Cached data of the byte address in memory(only valid when not a memory hole)!
	byte memLocHole; //Prefetched data!
} memorymapinfo[8]; //Two for reads(code, data), one for writes, double the size for adding DMA mapping support!

void resetMMU()
{
	void *memorycheckdummy;
	byte memory_allowresize = 1; //Do we allow resizing?
	if (__HW_DISABLED) return; //Abort!
	doneMMU(); //We're doing a full reset!
resetmmu:
	//dolog("MMU","Initialising MMU...");
	MMU.size = BIOS_GetMMUSize(); //Take over predefined: don't try to detect!

	if (((EMULATED_CPU==CPU_80386) && is_XT) || (is_Compaq==1)) //Compaq or XT reserved area?
	{
		if ((MMU.size<((0x100000-0xA0000)+(256*1024))) && (MMU.size)) //Not enough for reserved memory?
		{
			MMU.size = (0x100000-0xA0000)+(256*1024); //Minimum required memory!
		}
	}
	if ((EMULATED_CPU <= CPU_NECV30) && (MMU.size>0x100000)) MMU.size = 0x100000; //Limit unsupported sizes by the CPU!

	//dolog("zalloc","Allocating MMU memory...");
	MMU.memory = (byte *)zalloc(MMU.size, "MMU_Memory", NULL); //Allocate the memory available for the segments
	MMU.invaddr = 0; //Default: MMU address OK!
	user_memory_used = 0; //Default: no memory used yet!
	if (MMU.memory != NULL && (!force_memoryredetect) && MMU.size) //Allocated and not forcing redetect?
	{
		MMU_setA20(0, 0); //Default: Disabled A20 like 80(1)86!
		MMU_setA20(1, 0); //Default: Disabled A20 like 80(1)86!
	}
	else //Not allocated?
	{
		MMU_redetectMemory:
		MMU.size = 0; //We don't have size!
		doneMMU(); //Free up memory if allocated, to make sure we're not allocated anymore on the next try!
		if (memory_allowresize) //Can we resize memory?
		{
			autoDetectMemorySize(1); //Redetect memory size!
			force_memoryredetect = 0; //Not forcing redetect anymore: we've been redetected!
			memory_allowresize = 0; //Don't allow resizing anymore!
			goto resetmmu; //Try again!
		}
	}
	memorycheckdummy = zalloc(FREEMEMALLOC, "freememcheck", NULL); //Lockless free memory check!
	if (memorycheckdummy==NULL) //Not enough free memory?
	{
		goto MMU_redetectMemory; //Force memory redetection to make free memory!
	}
	freez(&memorycheckdummy, FREEMEMALLOC, "freememcheck"); //Release the checked memory!
	memory_allowresize = 1; //Allow resizing again!
	if (!MMU.size || !MMU.memory) //No size?
	{
		raiseError("MMU", "No memory available to use!");
	}
	MMUBuffer = allocfifobuffer(100 * 6, 0); //Alloc the write buffer with 100 entries (100 bytes)
	//Defaults first!
	BIOSROM_LowMemoryBecomesHighMemory = BIOSROM_DisableLowMemory = 0; //Default low memory behaviour!
	memoryprotect_FE0000 = 0; //Don't enable memory protection on FE0000+ by default!
	//Reset the register!
	MMU.maxsize = -1; //Default to not using any maximum size: full memory addressable!
	memset(&memorymapinfo, 0, sizeof(memorymapinfo)); //Initialize the memory map info properly!
	MMU_updatemaxsize(); //updated the maximum size!
	MMU_precalcMemoryHoles(); //Precalculate the memory hole information!
	updateBUShandler(); //Set the new bus handler!
	MMU_calcIndexPrecalcs(); //Calculate the index precalcs!
	memory_directwb(0x80C00000,0xFF); //Init to all bits set when emulated!
}

void doneMMU()
{
	if (__HW_DISABLED) return; //Abort!
	if (MMU.memory) //Got memory allocated?
	{
		freez((void **)&MMU.memory, MMU.size, "doneMMU_Memory"); //Release memory!
		MMU.size = 0; //Reset: none allocated!
	}
	if (MMUBuffer)
	{
		free_fifobuffer(&MMUBuffer); //Release us!
	}
}


uint_32 MEMsize() //Total size of memory in use?
{
	if (MMU.memory != NULL) //Have memory?
	{
		return MMU.size; //Give number of bytes!
	}
	else
	{
		return 0; //Error!
	}
}

OPTINLINE void MMU_INTERNAL_INVMEM(uint_32 originaladdress, uint_32 realaddress, byte iswrite, byte writevalue, byte index, byte ismemoryhole)
{
	#ifdef LOG_INVALID_MEMORY
	dolog("MMU","Invalid memory location addressed: %08X(=>%08X), Is write: %u, value on write: %02X index:%u, Memory hole: %u",originaladdress,realaddress,iswrite,writevalue,index,ismemoryhole);
	#endif
	return; //Don't ever give NMI's from memory!
	/*
	if (execNMI(1)) //Execute an NMI from memory!
	{
		MMU.invaddr = 1; //Signal invalid address!
	}
	*/
}

//isread: 0=write, 1=read, 3=Instruction read
OPTINLINE byte applyMemoryHoles(uint_32 realaddress, byte isread)
{
	INLINEREGISTER uint_32 originaladdress = (realaddress&~MMU_BLOCKALIGNMENT), maskedaddress; //Original address!
	byte memloc; //What memory block?
	byte memoryhole;
	realaddress = originaladdress; //Make sure we're aligned at chunks!

	if (likely((memorymapinfo[isread].byteaddr == originaladdress) && (memorymapinfo[isread].cache))) //Cached the requested adress block? We can return immediately, as we're ready to process!
	{
		return 0; //Found cached!
	}

	maskedaddress = (originaladdress >> 0x10); //Take the block number we're trying to access!
	if (unlikely(((memorymapinfo[isread].maskedaddress != maskedaddress)))) //Not matched already? Load the cache with it's information!
	{
		memorymapinfo[isread].maskedaddress = maskedaddress; //Map!
		memloc = memoryhole = memorymapinfo[isread].memLocHole = MMU_memorymapinfo[maskedaddress]; //Take from the mapped info into our cache!
		memloc &= 0xF; //The location of said memory!
		memoryhole >>= 4; //The map number that it's in, when it's a hole!
		memorymapinfo[isread].memLocHole = memoryhole; //Save the memory hole to use, if any!
		maskedaddress = memorymapinfo[isread].memorylocpatch = MMU_memorymaplocpatch[memloc]; //The patch address to substract!
		//Now that our cache is loaded with relevant data, start processing it!
		memorymapinfo[isread].cache = NULL; //Invalidate the cache by default! This is loaded later, when it's valid to use only!
	}
	else //Already loaded?
	{
		maskedaddress = memorymapinfo[isread].memorylocpatch; //Load the patch address!
		//Now that our cache is loaded with relevant data, start processing it!
		/*memloc =*/ memoryhole = memorymapinfo[isread].memLocHole; //Load it to split it into our two results!
		//memloc &= 0xF; //The location of said memory!
		//memoryhole >>= 4; //The map number that it's in, when it's not a hole!
	}

	memorymapinfo[isread].byteaddr = originaladdress; //New loaded cached address!

	if (unlikely(memoryhole)) //Memory hole?
	{
		// *nonexistant = 1; //We're non-existant!
		if (BIOSROM_LowMemoryBecomesHighMemory && (memoryhole==1)) //Compaq remaps RAM from E0000-FFFFF to FE0000-FFFFFF.
		{
			if ((originaladdress>=0xE0000) && (originaladdress<=0xFFFFF)) //Low memory hole to remap to the available memory hole memory? This is the size that's defined in MMU_RESERVEDMEMORY!
			{
				//memloc = 2; //We're the second block instead! Don't need to assign, as it's unused!
				originaladdress |= 0xF00000; //Patch to physical FE0000-FFFFFF reserved memory range to use!
				// *realaddress = originaladdress; //This is what we're remapping to!
			}
		}
		//Implemented (According to PCJs): Compaq has 384Kb of RAM at 0xFA0000-0xFFFFFF always. The rest of RAM is mapped low and above 16MB. The FE0000-FFFFFF range can be remapped to E0000-FFFFF, while it can be write-protected.
		if ((originaladdress>=0xFA0000) && (originaladdress<=0xFFFFFF)) //Special area addressed?
		{
			if (unlikely(memoryprotect_FE0000 && (!isread) && (originaladdress>=0xFE0000))) //Memory protected?
			{
				// *nonexistant = 1; //We're non-existant!
				return 1; //Abort!
			}
			//Reading or not protected?
			if (likely(((EMULATED_CPU==CPU_80386) && is_XT) || (is_Compaq==1))) //Compaq or XT reserved area?
			{
				/**realaddress*/ originaladdress += MMU.size-(0xFA0000+(0x100000-0xA0000)); //Patch to physical FE0000-FFFFFF reserved memory range to use, at the end of the physical memory!
				realaddress = originaladdress; //Save our new location!
				// *nonexistant = 3; //Reserved memory!
				if (unlikely((originaladdress>=MMU.size) /*|| ((originaladdress>=MMU.effectivemaxsize) && (nonexistant!=3))*/ /*|| (nonexistant==1)*/ )) //Overflow/invalid location?
					return 1; //Invalid memory location!
				//Valid chunk to address!

				//Load the new cache address now!
				memorymapinfo[isread].cache = &MMU.memory[originaladdress]; //Cached address in memory!
			}
			else
				return 1; //Unmapped memory!
			//if (unlikely((realaddress>=MMU.size) || ((realaddress>=MMU.effectivemaxsize) && (nonexistant!=3)) || (nonexistant==1))) //Overflow/invalid location?
		}
		else
		{
			return 1; //Not mapped!
		}
	}
	else //Plain memory?
	{
		// *nonexistant = 0; //We're to be used directly!
		originaladdress -= maskedaddress; //Patch into memory holes as required!
		if (unlikely(/*(realaddress>=MMU.size) ||*/ ((originaladdress>=MMU.effectivemaxsize) /*&& (nonexistant!=3)*/ ) /*|| (nonexistant==1)*/ )) //Overflow/invalid location?
		{
			return 1; //Not mapped or invalid!
		}
		//Load the new cache address now!
		memorymapinfo[isread].cache = &MMU.memory[originaladdress]; //Cached address for the memory!
		if (unlikely(/*(realaddress>=MMU.size) ||*/ (((originaladdress|MMU_BLOCKALIGNMENT)>=MMU.effectivemaxsize) /*&& (nonexistant!=3)*/ ) /*|| (nonexistant==1)*/ )) //Overflow/invalid location within block?
		{
			memorymapinfo[isread].byteaddr |= MMU_BLOCKALIGNMENT; //Make the overflow proper by handling it properly checking all addresses in it!
		}
	}
	return 0; //We're mapped!
}

extern byte specialdebugger; //Enable special debugger input?

void MMU_updatemaxsize() //updated the maximum size!
{
	byte memloc, memoryhole, isread;
	byte loc;
	MMU.effectivemaxsize = ((MMU.maxsize >= 0) ? MIN(MMU.maxsize, MMU.size) : MMU.size); //Precalculate the effective maximum size!
	for (loc=0;loc<=3;++loc)
	{
		MMU_memorymaplocpatch[loc] = MMU_calcmaplocpatch(loc);
	}
	//Invalidate the caches, since it's become invalid(due to updating memory locations)!
	isread = 0; //Init to the first cache!
	do //Update all caches and reload them from the precalcs!
	{
		memloc = memoryhole = memorymapinfo[isread].memLocHole = MMU_memorymapinfo[memorymapinfo[isread].maskedaddress]; //Take from the mapped info into our cache!
		memloc &= 0xF; //The location of said memory!
		memoryhole >>= 4; //The map number that it's in, when it's a hole!
		memorymapinfo[isread].memLocHole = memoryhole; //Save the memory hole to use, if any!
		memorymapinfo[isread].memorylocpatch = MMU_memorymaplocpatch[memloc]; //The patch address to substract!
		memorymapinfo[isread].cache = NULL; //Invalidate the cache!
	} while (++isread < 8); //Process all caches!
}

extern DRAM_accessHandler doDRAM_access; //DRAM access?

typedef void (*BUShandler)(byte index, byte value);

void BUSHandler_remember(byte index, byte value)
{
	mem_BUSValue &= BUSmask[index & 3]; //Apply the bus mask!
	mem_BUSValue |= ((uint_32)value << ((index & 3) << 3)); //Or into the last read/written value!
}

byte readCompaqMMURegister() //Read the Compaq MMU register!
{
	INLINEREGISTER byte result;
	//Reversed bits following: No memory parity error(bits 0-3=BUS address byte parity error, bit n=byte n(LE)).
//Bits 4-5=Base memory(0=256K, 1=512K, 2=Invalid, 3=640K. Bit 6=Second 1MB installed, Bit 7=Memory expansion board installed(adding 2M).
	if (MMU.maxsize >= 0xA0000) //640K base memory?
	{
		result = (3 << 4); //640K installed!
	}
	else if (MMU.maxsize >= 0x80000) //512K base memory?
	{
		result = (1 << 4); //512K installed!
	}
	else if (MMU.maxsize >= 0x40000) //256K base memory?
	{
		result = (0 << 4); //256K base memory?
	}
	else //Unknown?
	{
		result = (2 << 4); //Invalid!
	}
	if ((MMU.size & 0xFFF00000) >= 0x400000) //4MB installed?
	{
		result |= 0xC0; //Second 1MB installed, Memory expansion board installed(adding 2M).
	}
	else if ((MMU.size & 0xFFF00000) >= 0x300000) //3MB installed?
	{
		result |= 0x80; //Memory expansion board installed(adding 2M).
	}
	else if ((MMU.size & 0xFFF00000) >= 0x200000) //2MB installed?
	{
		result |= 0x40; //Second 1MB installed
	}
	result = ~result; //Reverse to get the correct output!
	return result; //Give the result!
}

extern byte BIU_cachedmemorysize; //For the BIU to flush it's cache!

void writeCompaqMMUregister(uint_32 originaladdress, byte value)
{
#ifdef LOG_HIGH_MEMORY
	if (unlikely((MMU_logging == 1) || (specialdebugger && (originaladdress >= 0x100000)))) //Data debugging?
	{
		debugger_logmemoryaccess(1, originaladdress, value, LOGMEMORYACCESS_RAM);
	}
#else
	if (unlikely(MMU_logging == 1)) //Data debugging?
	{
		debugger_logmemoryaccess(1, originaladdress, value, LOGMEMORYACCESS_RAM);
	}
#endif
	memoryprotect_FE0000 = ((~value) & 2); //Write-protect 128KB RAM at 0xFE0000?
	if (value & 1) //128KB RAM only addressed at FE0000? Otherwise, relocated to (F(general documentation)/0(IOPORTS.LST)?)E0000.
	{
		BIOSROM_LowMemoryBecomesHighMemory = BIOSROM_DisableLowMemory = 0; //Normal low memory!
	}
	else
	{
		BIOSROM_LowMemoryBecomesHighMemory = BIOSROM_DisableLowMemory = 1; //Low memory becomes high memory! Compaq RAM replaces ROM!
	}
	MoveLowMemoryHigh = 7; //Move all memory blocks high when needed?
	MMU.maxsize = MMU.size - (0x100000 - 0xA0000); //Limit the memory size!
	MMU_updatemaxsize(); //updated the maximum size!
	memory_datasize = 0; //Invalidate the read cache!
	BIU_cachedmemorysize = 0; //Make the BIU properly aware by flushing it's caches!
}

BUShandler bushandler = NULL; //Remember the last access?

byte index_readprecalcs[0x200]; //Read precalcs for index memory hole handling!
byte index_writeprecalcs[0x200]; //Read precalcs for index memory hole handling!
byte emulateCompaqMMURegisters = 0; //Emulate Compaq MMU registers?

//Direct memory access (for the entire emulator)
byte MMU_INTERNAL_directrb_debugger(uint_32 realaddress, word index, uint_32 *result) //Direct read from real memory (with real data direct)!
{
	uint_32 originaladdress = realaddress; //Original address!
	byte precalcval;
	byte nonexistant = 0;
	if (unlikely(emulateCompaqMMURegisters && (realaddress == 0x80C00000))) //Compaq special register?
	{
		*result = readCompaqMMURegister(); //Read the Compaq MMU register!
		memory_dataaddr = originaladdress; //What is the cached data address!
		memory_datasize = 1; //1 byte only!
		goto specialreadcycledebugger; //Apply the special read cycle!
	}
	precalcval = index_readprecalcs[index]; //Lookup the precalc val!
	if (unlikely(applyMemoryHoles(realaddress, precalcval))) //Overflow/invalid location?
	{
		MMU_INTERNAL_INVMEM(originaladdress, realaddress, 0, 0, (byte)index, nonexistant); //Invalid memory accessed!
		return 1; //Invalid memory, no response!
	}
	if (unlikely(doDRAM_access)) //DRAM access?
	{
		doDRAM_access(originaladdress); //Tick the DRAM!
	}

	*result = memorymapinfo[precalcval].cache[realaddress & MMU_BLOCKALIGNMENT]; //Get data from memory!
	memory_dataaddr = originaladdress; //What is the cached data address!
	memory_datasize = 1; //1 byte only!
	debugger_logmemoryaccess(0, (uint_32)((ptrnum)&memorymapinfo[precalcval].cache[realaddress & MMU_BLOCKALIGNMENT]-(ptrnum)MMU.memory), *result, LOGMEMORYACCESS_RAM_LOGMMUALL | (((index & 0x20) >> 5) << LOGMEMORYACCESS_PREFETCHBITSHIFT)); //Log it!
	//is_debugging |= 2; //Already gotten!
specialreadcycledebugger:
	debugger_logmemoryaccess(0, originaladdress, *result, LOGMEMORYACCESS_RAM | (((index & 0x20) >> 5) << LOGMEMORYACCESS_PREFETCHBITSHIFT)); //Log it!
	if (unlikely((index != 0xFF) && bushandler)) //Don't ignore BUS?
	{
		bushandler((byte)index, *result); //Update the bus!
	}
	return 0; //Give existant memory!
}

byte MMU_INTERNAL_directrb_nodebugger(uint_32 realaddress, word index, uint_32 *result) //Direct read from real memory (with real data direct)!
{
	uint_32 originaladdress = realaddress,temp; //Original address!
	byte nonexistant = 0;
	byte precalcval;
	if (unlikely(emulateCompaqMMURegisters && (realaddress == 0x80C00000))) //Compaq special register?
	{
		*result = readCompaqMMURegister(); //Read the Compaq MMU register!
		memory_dataaddr = originaladdress; //What is the cached data address!
		memory_datasize = 1; //1 byte only!
		goto specialreadcycle; //Apply the special read cycle!
	}
	precalcval = index_readprecalcs[index]; //Lookup the precalc val!
	if (unlikely(applyMemoryHoles(realaddress, precalcval))) //Overflow/invalid location?
	{
		MMU_INTERNAL_INVMEM(originaladdress, realaddress, 0, 0, (byte)index, nonexistant); //Invalid memory accessed!
		return 1; //Not mapped!
	}
	if ((memorymapinfo[precalcval].byteaddr & MMU_BLOCKALIGNMENT) == 0) //Cachable?
	{
		if (likely((index & 3) == 0))
		{
			temp = realaddress; //Backup address!
			realaddress &= ~3; //Round down to the dword address!
			if (likely((((realaddress & MMU_BLOCKALIGNMENT) | 3) <= MMU_BLOCKALIGNMENT))) //Enough to read a dword?
			{
				*result = SDL_SwapLE32(*((uint_32*)&memorymapinfo[precalcval].cache[realaddress & MMU_BLOCKALIGNMENT])); //Read the data from the ROM!
				memory_datasize = realaddress = 4 - (temp - realaddress); //What is read from the whole dword!
				*result >>= ((4 - realaddress) << 3); //Discard the bytes that are not to be read(before the requested address)!
				memory_dataaddr = originaladdress; //What is the cached data address!
			}
			else
			{
				realaddress = temp; //Restore the original address!
				realaddress &= ~1; //Round down to the word address!
				if (likely((((realaddress & MMU_BLOCKALIGNMENT) | 1) <= MMU_BLOCKALIGNMENT))) //Enough to read a word, aligned?
				{
					*result = SDL_SwapLE16(*((word*)(&memorymapinfo[precalcval].cache[realaddress & MMU_BLOCKALIGNMENT]))); //Read the data from the ROM!
					memory_datasize = realaddress = 2 - (temp - realaddress); //What is read from the whole word!
					*result >>= ((2 - realaddress) << 3); //Discard the bytes that are not to be read(before the requested address)!
					memory_dataaddr = originaladdress; //What is the cached data address!
				}
				else //Enough to read a byte only?
				{
					*result = memorymapinfo[precalcval].cache[temp & MMU_BLOCKALIGNMENT]; //Read the data from the ROM!
					memory_dataaddr = originaladdress; //What is the cached data address!
					memory_datasize = 1; //Only 1 byte!
				}
			}
		}
		else //Single, unaligned read?
		{
			*result = memorymapinfo[precalcval].cache[realaddress & MMU_BLOCKALIGNMENT]; //Get data from memory!
			memory_dataaddr = originaladdress; //What is the cached data address!
			memory_datasize = 1; //1 byte only!
		}
	}
	else //Not cacheable?
	{
		*result = memorymapinfo[precalcval].cache[realaddress & MMU_BLOCKALIGNMENT]; //Get data from memory!
		memory_dataaddr = originaladdress; //What is the cached data address!
		memory_datasize = 1; //1 byte only!
	}
	if (unlikely(doDRAM_access)) //DRAM access?
	{
		doDRAM_access(originaladdress); //Tick the DRAM!
	}
specialreadcycle:
	if (unlikely((index != 0xFF) && bushandler)) //Don't ignore BUS?
	{
		bushandler((byte)index, *result); //Update the bus!
	}
	return 0; //Give existant memory!
}

void updateBUShandler()
{
	if (is_XT && (EMULATED_CPU < CPU_80286))
	{
		bushandler = &BUSHandler_remember; //Remember the bus values!
	}
	else
	{
		bushandler = NULL; //Don't remember the bus handler!
	}
	emulateCompaqMMURegisters = ((EMULATED_CPU >= CPU_80386) && (is_Compaq == 1)); //Emulate compaq MMU registers?
}

void MMU_calcIndexPrecalcs()
{
	word index;
	for (index = 0; index < 0x200; ++index)
	{
		index_readprecalcs[index] = (((index & 0x20) >> 4) | 1) | ((index&0x100)>>6); //The read precalcs!
		index_writeprecalcs[index] = (((index & 0x20) >> 4) | 0) | ((index & 0x100) >> 6); //The write precalcs!
	}
}

typedef byte(*MMU_INTERNAL_directrb_handler)(uint_32 realaddress, word index, uint_32 *result); //A memory data read handler!
MMU_INTERNAL_directrb_handler MMU_INTERNAL_directrb_handlers[2] = { MMU_INTERNAL_directrb_nodebugger, MMU_INTERNAL_directrb_debugger }; //Debugging and non-debugging handlers to use!

OPTINLINE byte MMU_INTERNAL_directrb(uint_32 realaddress, word index, uint_32 *result)
{
	INLINEREGISTER byte is_debugging; //Are we debugging?
#ifdef LOG_HIGH_MEMORY
	is_debugging = ((MMU_logging == 1) || (specialdebugger && (realaddress >= 0x100000))); //Are we debugging?
#else
	is_debugging = (MMU_logging == 1); //Are we debugging?
#endif
	is_debugging &= 1; //1-bit only to know if we�re debugging or not!
	if (MMU_INTERNAL_directrb_handlers[is_debugging](realaddress, index, result)) //Give the debugger or non-debugger result!
	{
		return 1; //No response!
	}
	return 0; //Give the result that's gotten!
}

//Cache invalidation behaviour!
extern uint_32 BIU_cachedmemoryaddr;
extern uint_32 BIU_cachedmemoryread;
extern byte BIU_cachedmemorysize;

OPTINLINE void MMU_INTERNAL_directwb(uint_32 realaddress, byte value, word index) //Direct write to real memory (with real data direct)!
{
	byte precalcval;
	uint_32 originaladdress = realaddress; //Original address!
	//Apply the 640K memory hole!
	byte nonexistant = 0;
	if (unlikely(emulateCompaqMMURegisters && (realaddress==0x80C00000))) //Compaq special register?
	{
		writeCompaqMMUregister(originaladdress, value); //Update the Compaq MMU register!
		if (unlikely(BIU_cachedmemorysize && (BIU_cachedmemoryaddr <= originaladdress) && ((BIU_cachedmemoryaddr + BIU_cachedmemorysize) > originaladdress))) //Matched an active read cache(allowing self-modifying code)?
		{
			memory_datasize = 0; //Invalidate the read cache to re-read memory!
			BIU_cachedmemorysize = 0; //Invalidate the BIU cache as well!
		}
		return; //Count as a memory mapped register!
	}
	if (unlikely(((index&0xFF) != 0xFF) && bushandler)) //Don't ignore BUS?
	{
		bushandler((byte)index, value); //Update the bus handler!
	}
	if (unlikely(BIU_cachedmemorysize && (BIU_cachedmemoryaddr <= originaladdress) && ((BIU_cachedmemoryaddr+BIU_cachedmemorysize)>originaladdress))) //Matched an active read cache(allowing self-modifying code)?
	{
		memory_datasize = 0; //Invalidate the read cache to re-read memory!
		BIU_cachedmemorysize = 0; //Invalidate the BIU cache as well!
	}
	precalcval = index_writeprecalcs[index]; //Lookup the precalc val!
	if (unlikely(applyMemoryHoles(realaddress,precalcval))) //Overflow/invalid location?
	{
		MMU_INTERNAL_INVMEM(originaladdress,realaddress,1,value,(index&0xFF),nonexistant); //Invalid memory accessed!
		return; //Abort!
	}
#ifdef LOG_HIGH_MEMORY
	if (unlikely((MMU_logging==1) || (specialdebugger && (originaladdress>=0x100000)))) //Data debugging?
	{
		debugger_logmemoryaccess(1,originaladdress,value,LOGMEMORYACCESS_RAM);
		debugger_logmemoryaccess(1,realaddress,value,LOGMEMORYACCESS_RAM_LOGMMUALL); //Log it!
	}
#else
	if (unlikely(MMU_logging == 1)) //Data debugging?
	{
		debugger_logmemoryaccess(1, originaladdress, value, LOGMEMORYACCESS_RAM);
		debugger_logmemoryaccess(1, (uint_32)((ptrnum)&memorymapinfo[0].cache[realaddress & MMU_BLOCKALIGNMENT] - (ptrnum)MMU.memory), value, LOGMEMORYACCESS_RAM_LOGMMUALL); //Log it!
	}
#endif
	memorymapinfo[precalcval].cache[realaddress & MMU_BLOCKALIGNMENT] = value; //Set data, full memory protection!
	if (unlikely(doDRAM_access)) //DRAM access?
	{
		doDRAM_access(realaddress); //Tick the DRAM!
	}
	if (unlikely((realaddress+1)>user_memory_used)) //More written than present in memory (first write to addr)?
	{
		user_memory_used = (realaddress+1); //Update max memory used!
	}
}

//Used by the DMA controller only(rw/rdw). Result is the value only.
word MMU_INTERNAL_directrw(uint_32 realaddress, word index) //Direct read from real memory (with real data direct)!
{
	word result;
	uint_32 temp;
	if (MMU_INTERNAL_directrb(realaddress, index, &temp)) //Get data, wrap arround!
	{
		if (likely((is_XT == 0) || (EMULATED_CPU >= CPU_80286))) //To give NOT for detecting memory on AT only?
		{
			temp = 0xFF; //Give the last data read/written by the BUS!
			memory_dataread = temp; //What is read!
			memory_dataaddr = realaddress; //What address!
			memory_datasize = 1; //1 byte only!
		}
		else
		{
			temp = (byte)(mem_BUSValue >> ((index & 3) << 3)); //Give the last data read/written by the BUS!
			memory_dataread = temp; //What is read!
			memory_dataaddr = realaddress; //What address!
			memory_datasize = 1; //1 byte only!
		}
	}
	result = temp; //The low byte too!
	if (MMU_INTERNAL_directrb(realaddress + 1, index | 1, &temp))
	{
		if (likely((is_XT == 0) || (EMULATED_CPU >= CPU_80286))) //To give NOT for detecting memory on AT only?
		{
			temp = 0xFF; //Give the last data read/written by the BUS!
			memory_dataaddr = realaddress; //What address!
			memory_dataread = temp; //What is read!
			memory_datasize = 1; //1 byte only!
		}
		else
		{
			temp = (byte)(mem_BUSValue >> ((index & 3) << 3)); //Give the last data read/written by the BUS!
			memory_dataaddr = realaddress; //What address!
			memory_datasize = 1; //1 byte only!
		}
	}
	result |= (temp << 8); //Higher byte!
	memory_dataread = result;
	memory_datasize = 2; //How much is read!
	return result; //Give the result!
}

void MMU_INTERNAL_directww(uint_32 realaddress, word value, word index) //Direct write to real memory (with real data direct)!
{
	MMU_INTERNAL_directwb(realaddress, value & 0xFF, index); //Low!
	MMU_INTERNAL_directwb(realaddress + 1, (value >> 8) & 0xFF, index | 1); //High!
}

//Used by paging only!
uint_32 MMU_INTERNAL_directrdw(uint_32 realaddress, word index)
{
	return (MMU_INTERNAL_directrw(realaddress + 2, index | 2) << 16) | MMU_INTERNAL_directrw(realaddress, index); //Get data, wrap arround!	
}
void MMU_INTERNAL_directwdw(uint_32 realaddress, uint_32 value, word index)
{
	MMU_INTERNAL_directww(realaddress, value & 0xFFFF, index); //Low!
	MMU_INTERNAL_directww(realaddress + 2, (value >> 16) & 0xFFFF, index | 2); //High!
}

byte MMUbuffer_pending = 0; //Anything pending?

//Direct memory access with Memory mapped I/O (for the CPU).
byte MMU_INTERNAL_directrb_realaddr(uint_32 realaddress, byte index) //Read without segment/offset translation&protection (from system/interrupt)!
{
	if (likely(MMU_IO_readhandler(realaddress, index))) //Normal memory address?
	{
		if (unlikely(MMU_INTERNAL_directrb(realaddress, index, &memory_dataread))) //Read the data from memory (and port I/O)!		
		{
			if (likely((is_XT == 0) || (EMULATED_CPU >= CPU_80286))) //To give NOT for detecting memory on AT only?
			{
				memory_dataread = 0xFF; //Give the last data read/written by the BUS!
				memory_dataaddr = realaddress; //What address!
				memory_datasize = 1; //Only 1 byte long!
			}
			else
			{
				memory_dataread = (byte)(mem_BUSValue >> ((index & 3) << 3)); //Give the last data read/written by the BUS!
				memory_dataaddr = realaddress; //What address!
				memory_datasize = 1; //Only 1 byte long!
			}
		}
	}
//Are we debugging?
#ifdef LOG_HIGH_MEMORY
	#define is_debugging ((MMU_logging == 1) || (specialdebugger && (realaddress >= 0x100000)))
#else
	#define is_debugging (MMU_logging == 1)
#endif
	if (unlikely(is_debugging)) //To log?
	{
		debugger_logmemoryaccess(0,realaddress,memory_dataread,LOGMEMORYACCESS_DIRECT|(((index&0x20)>>5)<<LOGMEMORYACCESS_PREFETCHBITSHIFT)); //Log it!
	}
	return memory_dataread;
#undef is_debugging
}

void MMU_INTERNAL_directwb_realaddr(uint_32 realaddress, byte val, byte index) //Write without segment/offset translation&protection (from system/interrupt)!
{
	union
	{
		uint_32 realaddress; //The address!
		byte addr[4];
	} addressconverter;
	byte status;
	//Are we debugging?
#ifdef LOG_HIGH_MEMORY
#define is_debugging ((MMU_logging == 1) || (specialdebugger && (realaddress >= 0x100000))
#else
#define is_debugging (MMU_logging == 1)
#endif
	if (enableMMUbuffer && MMUBuffer) //To buffer all writes?
	{
		if (fifobuffer_freesize(MMUBuffer) >= 7) //Enough size left to buffer?
		{
			MMUbuffer_pending = 1; //We're pending from now on!
			addressconverter.realaddress = realaddress; //The address to break up!
			status = 1; //1 byte written!
			if (!writefifobuffer(MMUBuffer, status)) return; //Invalid data!
			if (!writefifobuffer(MMUBuffer, addressconverter.addr[0])) return; //Invalid data!
			if (!writefifobuffer(MMUBuffer, addressconverter.addr[1])) return; //Invalid data!
			if (!writefifobuffer(MMUBuffer, addressconverter.addr[2])) return; //Invalid data!
			if (!writefifobuffer(MMUBuffer, addressconverter.addr[3])) return; //Invalid data!
			if (!writefifobuffer(MMUBuffer, val)) return; //Invalid data!
			if (!writefifobuffer(MMUBuffer, index)) return; //Invalid data!
			return;
		}
	}
	if (unlikely(is_debugging)) //To log?
	{
		debugger_logmemoryaccess(1,realaddress,val,LOGMEMORYACCESS_DIRECT); //Log it!
	}
	if (MMU_ignorewrites) return; //Ignore all written data: protect memory integrity!
	if (likely(MMU_IO_writehandler(realaddress, val))) //Normal memory access?
	{
		MMU_INTERNAL_directwb(realaddress, val, index); //Set data in real memory!
	}
#undef is_debugging
}

void flushMMU() //Flush MMU writes!
{
	union
	{
		uint_32 realaddress; //The address!
		byte addr[4];
	} addressconverter;
	byte status;
	byte val, index;
	//Read the buffer
	enableMMUbuffer = 0; //Finished buffering!
	if (unlikely(MMUbuffer_pending)) //Anything pending?
	{
		MMUbuffer_pending = 0; //Not anymore!
		for (; readfifobuffer(MMUBuffer, &status);) //Gotten data to write(byte/word/dword data)?
		{
			//Status doesn't have any meaning yet, so ignore it(always byte data)!
			if (!readfifobuffer(MMUBuffer, &addressconverter.addr[0])) break; //Invalid data!
			if (!readfifobuffer(MMUBuffer, &addressconverter.addr[1])) break; //Invalid data!
			if (!readfifobuffer(MMUBuffer, &addressconverter.addr[2])) break; //Invalid data!
			if (!readfifobuffer(MMUBuffer, &addressconverter.addr[3])) break; //Invalid data!
			if (!readfifobuffer(MMUBuffer, &val)) break; //Invalid data!
			if (!readfifobuffer(MMUBuffer, &index)) break; //Invalid data!
			MMU_INTERNAL_directwb_realaddr(addressconverter.realaddress, val, index); //Write the value to memory!
		}
	}
}

void bufferMMU() //Buffer MMU writes!
{
	enableMMUbuffer = 1; //Buffer MMU writes!
}

extern char capturepath[256]; //Full capture path!

//Dump memory
void MMU_dumpmemory(char *filename) //Dump the memory to a file!
{
	char filenamefull[256];
	cleardata(&filenamefull[0],sizeof(filenamefull)); //Clear memory!
	snprintf(filenamefull,sizeof(filenamefull),"%s/%s",capturepath,filename); //Capture path file!
	domkdir(capturepath); //Make sure we exist!
	BIGFILE *f;
	f = emufopen64(filenamefull,"wb"); //Open file!
	emufwrite64(MMU.memory,1,user_memory_used,f); //Write memory to file!
	emufclose64(f); //Close file!
}

//Have memory available?
byte hasmemory()
{
	if (MMU.memory==NULL) //No memory?
	{
		return 0; //No memory!
	}
	if (MMU.size==0) //No memory?
	{
		return 0; //No memory!
	}
	return 1; //Have memory!
}

//Memory has gone wrong in direct access?
byte MMU_invaddr()
{
	return (byte)MMU.invaddr; //Given an invalid adress?
}

void MMU_resetaddr()
{
	MMU.invaddr = 0; //Reset: we're valid again!
}

//Direct memory access routines (used by DMA)!
byte memory_directrb(uint_32 realaddress) //Direct read from real memory (with real data direct)!
{
	uint_32 result;
	if (unlikely(MMU_INTERNAL_directrb(realaddress, 0x100, &result)))
	{
		if (likely((is_XT == 0) || (EMULATED_CPU >= CPU_80286))) //To give NOT for detecting memory on AT only?
		{
			result = 0xFF; //Give the last data read/written by the BUS!
		}
		else
		{
			result = (byte)(mem_BUSValue >> ((0 & 3) << 3)); //Give the last data read/written by the BUS!
		}
	}
	return result; //Give the result!
}
word memory_directrw(uint_32 realaddress) //Direct read from real memory (with real data direct)!
{
	return MMU_INTERNAL_directrw(realaddress, 0x100);
}
uint_32 memory_directrdw(uint_32 realaddress) //Direct read from real memory (with real data direct)!
{
	return MMU_INTERNAL_directrdw(realaddress, 0x100);
}
void memory_directwb(uint_32 realaddress, byte value) //Direct write to real memory (with real data direct)!
{
	MMU_INTERNAL_directwb(realaddress, value, 0x100);
}
void memory_directww(uint_32 realaddress, word value) //Direct write to real memory (with real data direct)!
{
	MMU_INTERNAL_directww(realaddress, value, 0x100);
}
void memory_directwdw(uint_32 realaddress, uint_32 value) //Direct write to real memory (with real data direct)!
{
	MMU_INTERNAL_directwdw(realaddress, value, 0x100);
}
