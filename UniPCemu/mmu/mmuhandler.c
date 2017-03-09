#define IS_MMU
#include "headers/types.h" //Basic types!
#include "headers/cpu/mmu.h" //MMU support!
#include "headers/mmu/mmuhandler.h" //Our typedefs!
#include "headers/support/zalloc.h" //Memory allocation!
#include "headers/hardware/dram.h" //DRAM support!
#include "headers/support/log.h" //Logging support!
#include "headers/support/fifobuffer.h" //Write buffer support!

extern BIOS_Settings_TYPE BIOS_Settings; //Settings!
extern MMU_type MMU; //MMU for direct access!

#define __HW_DISABLED 0

//Log invalid memory accesses?
#define LOG_INVALID_MEMORY

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
	MMUHANDLER.numw=NUMITEMS(MMUHANDLER.writehandlers); //Init!
	for (;MMUHANDLER.numw;)
	{
		if (MMUHANDLER.writehandlers[MMUHANDLER.numw-1]) //Found?
		{
			return; //Stop searching!
		}
		--MMUHANDLER.numw; //Next!
	}
}

OPTINLINE void MMUHANDLER_countreads()
{
	MMUHANDLER.numr=NUMITEMS(MMUHANDLER.readhandlers); //Init!
	for (;MMUHANDLER.numr;)
	{
		if (MMUHANDLER.readhandlers[MMUHANDLER.numr-1]) //Found?
		{
			return; //Stop searching!
		}
		--MMUHANDLER.numr; //Next!
	}
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
			strcpy(MMUHANDLER.modulew[i],module); //Set module!
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
			strcpy(MMUHANDLER.moduler[i],module); //Set module!
			MMUHANDLER_countreads(); //Recount!
			return 1; //Registered!
		}
	}
	return 0; //Error: ran out of space!
}

//Handler for special MMU-based I/O, direct addresses used!
byte MMU_IO_writehandler(uint_32 offset, byte value)
{
	MMU_WHANDLER *current; //Current item!
	INLINEREGISTER MMU_WHANDLER handler;
	INLINEREGISTER byte j = MMUHANDLER.numw; //The amount of handlers to process!
	if (!j) return 1; //Normal memory access by default!
	current = &MMUHANDLER.writehandlers[0]; //Start of our list!
	do //Search all available handlers!
	{
		handler = *current++; //Load the current address!
		if (handler == 0) continue; //Set?
		if (handler(offset,value)) //Success?
		{
			return 0; //Abort searching: we're processed!
		}
	} while (--j);
	return 1; //Normal memory access!
}

//Reading only!
byte MMU_IO_readhandler(uint_32 offset, byte *value)
{
	MMU_RHANDLER *current; //Current item!
	INLINEREGISTER MMU_RHANDLER handler;
	INLINEREGISTER byte j = MMUHANDLER.numr; //The amount of handlers to process!
	if (!j) return 1; //Normal memory access by default!
	current = &MMUHANDLER.readhandlers[0]; //Start of our list!
	do //Search all available handlers!
	{
		handler = *current++; //Load the current address!
		if (handler == 0) continue; //Set?
		if (handler(offset,value)) //Success reading?
		{
			return 0; //Abort searching: we're processed!
		}
	} while (--j); //Loop while not done!
	return 1; //Normal memory access!
}

extern byte is_XT; //Are we emulating a XT architecture?
extern byte is_Compaq; //Are we emulating a Compaq architecture?

byte MoveLowMemoryHigh; //Disable HMA memory and enable the memory hole?

byte memoryprotect_FE0000 = 1; //Memory-protect block at FE0000?
byte BIOSROM_LowMemoryBecomesHighMemory = 0; //Disable low-memory mapping of the BIOS and OPTROMs! Disable mapping of low memory locations E0000-FFFFF used on the Compaq Deskpro 386.
extern byte BIOSROM_DisableLowMemory; //Disable low-memory mapping of the BIOS and OPTROMs! Disable mapping of low memory locations E0000-FFFFF used on the Compaq Deskpro 386.

void resetMMU()
{
	byte memory_allowresize = 1; //Do we allow resizing?
	if (__HW_DISABLED) return; //Abort!
	doneMMU(); //We're doing a full reset!
resetmmu:
	//dolog("MMU","Initialising MMU...");
	MMU.size = BIOS_GetMMUSize(); //Take over predefined: don't try to detect!

	if ((EMULATED_CPU <= CPU_NECV30) && (MMU.size>0x100000)) MMU.size = 0x100000; //Limit unsupported sizes by the CPU!
																				  //dolog("zalloc","Allocating MMU memory...");
	MMU.memory = (byte *)zalloc((MMU.size+MMU_RESERVEDMEMORY), "MMU_Memory", NULL); //Allocate the memory available for the segments
	MMU.invaddr = 0; //Default: MMU address OK!
	user_memory_used = 0; //Default: no memory used yet!
	if (MMU.memory != NULL && !force_memoryredetect) //Allocated and not forcing redetect?
	{
		MMU_setA20(0, 0); //Default: Disabled A20 like 80(1)86!
		MMU_setA20(1, 0); //Default: Disabled A20 like 80(1)86!
	}
	else //Not allocated?
	{
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
	memory_allowresize = 1; //Allow resizing again!
	if (!MMU.size || !MMU.memory) //No size?
	{
		raiseError("MMU", "No memory available to use!");
	}
	MMUBuffer = allocfifobuffer(100 * 6, 0); //Alloc the write buffer with 100 entries (100 bytes)
	BIOSROM_LowMemoryBecomesHighMemory = BIOSROM_DisableLowMemory = 0; //Default low memory behaviour!
	memoryprotect_FE0000 = 1; //Enable memory protection on FE0000+ by default!
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
	dolog("MMU","Invalid memory location addressed: %08X(=>%08X), Is write: %i, value on write: %02X index:%i, Memory hole: %i",originaladdress,realaddress,iswrite,writevalue,index,ismemoryhole);
	#endif
	return; //Don't ever give NMI's from memory!
	/*
	if (execNMI(1)) //Execute an NMI from memory!
	{
		MMU.invaddr = 1; //Signal invalid address!
	}
	*/
}

OPTINLINE char stringsafe(byte x)
{
	return (x && (x!=0xD) && (x!=0xA))?x:(char)0x20;
}

//Memory hole start/end locations!
#define LOW_MEMORYHOLE_START 0xA0000
#define LOW_MEMORYHOLE_END 0x100000
#define MID_MEMORYHOLE_START 0xF00000
#define MID_MEMORYHOLE_END 0x1000000
#define HIGH_MEMORYHOLE_START 0xC0000000
#define HIGH_MEMORYHOLE_END 0x100000000

OPTINLINE void applyMemoryHoles(uint_32 *realaddress, byte *nonexistant, byte iswrite)
{
	INLINEREGISTER byte memloc; //What memory block?
	INLINEREGISTER byte memoryhole;
	memloc = 0; //Default: first memory block: low memory!
	memoryhole = 0; //Default: memory unavailable!
	if (*realaddress>=LOW_MEMORYHOLE_START) //Start of first hole?
	{
		if (*realaddress<LOW_MEMORYHOLE_END) //First hole?
		{
			memoryhole = 1; //First memory hole!
		}
		else //Mid memory?
		{
			memloc = 1; //Second memory block: mid memory!
			if (*realaddress>=MID_MEMORYHOLE_START) //Start of second hole?
			{
				if (*realaddress<MID_MEMORYHOLE_END) //Second hole?
				{
					memoryhole = 2; //Second memory hole!
				}
				else //High memory?
				{
					memloc = 2; //Third memory block!
					if ((*realaddress>=HIGH_MEMORYHOLE_START) && ((uint_64)*realaddress<(uint_64)HIGH_MEMORYHOLE_END)) //Start of third hole?
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

	if (memoryprotect_FE0000 && (*realaddress>=0xFE0000) && (*realaddress<=0xFFFFFF) && iswrite) //Memory protected?
	{
		*nonexistant = 1; //We're non-existant!
		return; //Abort!
	}
	if (memoryhole) //Memory hole?
	{
		*nonexistant = 1; //We're non-existant!
		if (BIOSROM_LowMemoryBecomesHighMemory && (memoryhole==1)) //Move memory FE0000-FFFFFF to E0000-FFFFF?
		{
			if ((*realaddress>=0xE0000) && (*realaddress<=0xFFFFF)) //Low memory hole to remap to the available memory hole memory? This is the size that's defined in MMU_RESERVEDMEMORY!
			{
				memloc = 2; //We're the second block instead!
				*realaddress += MIN(MMU.size,MMU.maxsize?MMU.maxsize:MMU.size)-0xE0000; //Patch to physical FE0000-FFFFFF reserved memory range to use!
				return; //Apply the new block instead!
			}
		}
	}
	else //Plain memory?
	{
		*nonexistant = 0; //We're to be used directly!
		if ((MoveLowMemoryHigh&1) && (memloc)) //Move first block lower?
		{
			*realaddress -= (LOW_MEMORYHOLE_END - LOW_MEMORYHOLE_START); //Patch into memory hole!
		}
		if ((MoveLowMemoryHigh&2) && (memloc>=2)) //Move second block lower?
		{
			*realaddress -= (MID_MEMORYHOLE_END - MID_MEMORYHOLE_START); //Patch into memory hole!
		}
		if ((MoveLowMemoryHigh&4) && (memloc>=3)) //Move third block lower?
		{
			*realaddress -= (uint_32)((uint_64)HIGH_MEMORYHOLE_END - (uint_64)HIGH_MEMORYHOLE_START); //Patch into memory hole!
		}
		if ((*realaddress >= MMU.size) || ((*realaddress>=MMU.maxsize) && MMU.maxsize)) //Reserved memory?
		{
			*nonexistant = 2; //Reserved for reading only!
		}
	}
}

//Direct memory access (for the entire emulator)
byte MMU_INTERNAL_directrb(uint_32 realaddress, byte index) //Direct read from real memory (with real data direct)!
{
	uint_32 originaladdress = realaddress; //Original address!
	byte result;
	byte nonexistant = 0;
	if ((realaddress==0x80C00000) && (EMULATED_CPU>=CPU_80386) && (is_Compaq==1)) //Compaq special register?
	{
		result = ((MIN(MMU.size,MMU.maxsize?MMU.maxsize:MMU.size)+MMU_RESERVEDMEMORY)>=0xA0000)?0x40:0x00; //Second 1MB memory installed?
		goto specialreadcycle; //Apply the special read cycle!
	}
	applyMemoryHoles(&realaddress,&nonexistant,0); //Apply the memory holes!
	if ((realaddress >= (MMU.size+MMU_RESERVEDMEMORY)) || ((realaddress>=(MMU.maxsize+MMU_RESERVEDMEMORY)) && MMU.maxsize) || nonexistant) //Overflow/invalid location?
	{
		MMU_INTERNAL_INVMEM(originaladdress,realaddress,0,0,index,nonexistant); //Invalid memory accessed!
		if ((is_XT==0) || (EMULATED_CPU>=CPU_80286)) //To give NOT for detecting memory on AT only?
		{
			return 0xFF; //Give the last data read/written by the BUS!
		}
		else
		{
			return (byte)(mem_BUSValue >> ((index & 3) << 3)); //Give the last data read/written by the BUS!
		}
	}
	result = MMU.memory[realaddress]; //Get data from memory!
	specialreadcycle:
	DRAM_access(realaddress); //Tick the DRAM!
	if (index != 0xFF) //Don't ignore BUS?
	{
		mem_BUSValue &= BUSmask[index & 3]; //Apply the bus mask!
		mem_BUSValue |= ((uint_32)result << ((index & 3) << 3)); //Or into the last read/written value!
	}
	if (MMU_logging) //To log?
	{
		dolog("debugger", "Reading from RAM: %08X=%02X (%c)", realaddress, result, stringsafe(result)); //Log it!
	}
	return result; //Give existant memory!
}

void MMU_INTERNAL_directwb(uint_32 realaddress, byte value, byte index) //Direct write to real memory (with real data direct)!
{
	uint_32 originaladdress = realaddress; //Original address!
	if (LOG_MMU_WRITES) //Data debugging?
	{
		dolog("debugger", "MMU: Writing to real %08X=%02X (%c)", realaddress, value, stringsafe(value));
	}
	//Apply the 640K memory hole!
	byte nonexistant = 0;
	if ((realaddress==0x80C00000) && (EMULATED_CPU>=CPU_80386) && (is_Compaq==1)) //Compaq special register?
	{
		if (value&1) //Write-protect 128KB RAM at 0xFE0000?
		{
			memoryprotect_FE0000 = (value&1); //Protect the memory?
		}
		if (value&2) //128KB RAM only addressed at FE0000? Otherwise, relocated to (F(general documentation)/0(IOPORTS.LST)?)E0000.
		{
			BIOSROM_LowMemoryBecomesHighMemory = BIOSROM_DisableLowMemory = 0; //Normal low memory!
		}
		else
		{
			BIOSROM_LowMemoryBecomesHighMemory = BIOSROM_DisableLowMemory = 1; //Low memory becomes high memory!
		}
	}
	applyMemoryHoles(&realaddress,&nonexistant,1); //Apply the memory holes!
	if (index != 0xFF) //Don't ignore BUS?
	{
		mem_BUSValue &= BUSmask[index & 3]; //Apply the bus mask!
		mem_BUSValue |= ((uint_32)value << ((index & 3) << 3)); //Or into the last read/written value!
	}
	if ((realaddress >= (MMU.size+MMU_RESERVEDMEMORY)) || ((realaddress>=(MMU.maxsize+MMU_RESERVEDMEMORY)) && MMU.maxsize) || nonexistant) //Overflow/invalid location?
	{
		MMU_INTERNAL_INVMEM(originaladdress,realaddress,1,value,index,nonexistant); //Invalid memory accessed!
		return; //Abort!
	}
	if (MMU_logging) //To log?
	{
		dolog("debugger", "Writing to RAM: %08X=%02X (%c)", realaddress, value, stringsafe(value)); //Log it!
	}
	MMU.memory[realaddress] = value; //Set data, full memory protection!
	DRAM_access(realaddress); //Tick the DRAM!
	if (realaddress>user_memory_used) //More written than present in memory (first write to addr)?
	{
		user_memory_used = realaddress; //Update max memory used!
	}
}

//Used by the DMA controller only (or the paging system for faster reads):
word MMU_INTERNAL_directrw(uint_32 realaddress, byte index) //Direct read from real memory (with real data direct)!
{
	return (MMU_INTERNAL_directrb(realaddress + 1, index | 1) << 8) | MMU_INTERNAL_directrb(realaddress, index); //Get data, wrap arround!
}

void MMU_INTERNAL_directww(uint_32 realaddress, word value, byte index) //Direct write to real memory (with real data direct)!
{
	MMU_INTERNAL_directwb(realaddress, value & 0xFF, index); //Low!
	MMU_INTERNAL_directwb(realaddress + 1, (value >> 8) & 0xFF, index | 1); //High!
}

//Used by paging only!
uint_32 MMU_INTERNAL_directrdw(uint_32 realaddress, byte index)
{
	return (MMU_INTERNAL_directrw(realaddress + 2, index | 2) << 16) | MMU_INTERNAL_directrw(realaddress, index); //Get data, wrap arround!	
}
void MMU_INTERNAL_directwdw(uint_32 realaddress, uint_32 value, byte index)
{
	MMU_INTERNAL_directww(realaddress, value & 0xFF, index); //Low!
	MMU_INTERNAL_directww(realaddress + 2, (value >> 8) & 0xFF, index | 2); //High!
}

//Direct memory access with Memory mapped I/O (for the CPU).
byte MMU_INTERNAL_directrb_realaddr(uint_32 realaddress, byte opcode, byte index) //Read without segment/offset translation&protection (from system/interrupt)!
{
	byte data;
	if (MMU_IO_readhandler(realaddress, &data)) //Normal memory address?
	{
		data = MMU_INTERNAL_directrb(realaddress, index); //Read the data from memory (and port I/O)!		
	}
	if (MMU_logging && (!opcode)) //To log?
	{
		dolog("debugger", "Read from memory: %08X=%02X (%c)", realaddress, data, stringsafe(data)); //Log it!
	}
	return data;
}

void MMU_INTERNAL_directwb_realaddr(uint_32 realaddress, byte val, byte index) //Write without segment/offset translation&protection (from system/interrupt)!
{
	union
	{
		uint_32 realaddress; //The address!
		byte addr[4];
	} addressconverter;
	byte status;
	if (enableMMUbuffer && MMUBuffer) //To buffer all writes?
	{
		if (fifobuffer_freesize(MMUBuffer) >= 7) //Enough size left to buffer?
		{
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
	if (MMU_logging) //To log?
	{
		dolog("debugger", "Writing to memory: %08X=%02X (%c)", realaddress, val, stringsafe(val)); //Log it!
	}
	if (MMU_ignorewrites) return; //Ignore all written data: protect memory integrity!
	if (MMU_IO_writehandler(realaddress, val)) //Normal memory access?
	{
		MMU_INTERNAL_directwb(realaddress, val, index); //Set data in real memory!
	}
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
	for (;readfifobuffer(MMUBuffer, &status);) //Gotten data to write(byte/word/dword data)?
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

void bufferMMU() //Buffer MMU writes!
{
	enableMMUbuffer = 1; //Buffer MMU writes!
}

extern char capturepath[256]; //Full capture path!

//Dump memory
void MMU_dumpmemory(char *filename) //Dump the memory to a file!
{
	char filenamefull[256];
	bzero(&filenamefull,sizeof(filenamefull)); //Clear memory!
	sprintf(filenamefull,"%s/%s",capturepath,filename); //Capture path file!
	domkdir(capturepath); //Make sure we exist!
	FILE *f;
	f = fopen(filenamefull,"wb"); //Open file!
	fwrite(MMU.memory,1,user_memory_used,f); //Write memory to file!
	fclose(f); //Close file!
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

//Direct memory access routines (used by DMA and Paging)!
byte memory_directrb(uint_32 realaddress) //Direct read from real memory (with real data direct)!
{
	return MMU_INTERNAL_directrb(realaddress, 0);
}
word memory_directrw(uint_32 realaddress) //Direct read from real memory (with real data direct)!
{
	return MMU_INTERNAL_directrw(realaddress, 0);
}
uint_32 memory_directrdw(uint_32 realaddress) //Direct read from real memory (with real data direct)!
{
	return MMU_INTERNAL_directrdw(realaddress, 0);
}
void memory_directwb(uint_32 realaddress, byte value) //Direct write to real memory (with real data direct)!
{
	MMU_INTERNAL_directwb(realaddress, value, 0);
}
void memory_directww(uint_32 realaddress, word value) //Direct write to real memory (with real data direct)!
{
	MMU_INTERNAL_directww(realaddress, value, 0);
}
void memory_directwdw(uint_32 realaddress, uint_32 value) //Direct write to real memory (with real data direct)!
{
	MMU_INTERNAL_directwdw(realaddress, value, 0);
}
