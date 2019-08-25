/*
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

#include "headers/types.h" //Basic types!
#include "headers/mmu/mmuhandler.h" //MMU support!
#include "headers/hardware/ports.h" //I/O port support!
#include "headers/hardware/ems.h" //EMS support prototypes!
#include "headers/support/zalloc.h" //Memory allocation support!
#include "headers/support/locks.h" //Locking support!

word EMS_baseport = 0x260; //Base I/O port!
uint_32 EMS_baseaddr = 0xE0000; //Base address!

byte *EMS = NULL; //EMS memory itself!
uint_32 EMS_size = 0; //Size of EMS memory!

byte EMS_pages[4] = { 0,0,0,0 }; //What pages are mapped?

byte readEMSMem(uint_32 address, byte *value)
{
	byte block;
	uint_32 memoryaddress;
	if (address < EMS_baseaddr) return 0; //No EMS!
	address -= EMS_baseaddr; //Get the EMS address!
	if (address >= 0x10000) return 0; //No EMS!
	block = (address >> 14); //What block are we?
	address &= 0x3FFF; //What address witin the page?
	memoryaddress = (EMS_pages[block] << 14); //Block in memory!
	memoryaddress |= address; //The address of the byte in memory!
	if (memoryaddress >= EMS_size) return 0; //Out of range?
	*value = EMS[memoryaddress]; //Give the byte from memory!
	return 1; //We're mapped!
}

byte writeEMSMem(uint_32 address, byte value)
{
	byte block;
	uint_32 memoryaddress;
	if (address < EMS_baseaddr) return 0; //No EMS!
	address -= EMS_baseaddr; //Get the EMS address!
	if (address >= 0x10000) return 0; //No EMS!
	block = (address >> 14); //What block are we?
	address &= 0x3FFF; //What address witin the page?
	memoryaddress = (EMS_pages[block] << 14); //Block in memory!
	memoryaddress |= address; //The address of the byte in memory!
	if (memoryaddress >= EMS_size) return 0; //Out of range?
	EMS[memoryaddress] = value; //Set the byte in memory!
	return 1; //We're mapped!
}

byte readEMSIO(word port, byte *value)
{
	if (port<EMS_baseport) return 0; //No EMS!
	port -= EMS_baseport; //Get the EMS port!
	if (port>=NUMITEMS(EMS_pages)) return 0; //No EMS!
	*value = EMS_pages[port]; //Get the page!
	return 1; //Give the value!
}

byte writeEMSIO(word port, byte value)
{
	if (port<EMS_baseport) return 0; //No EMS!
	port -= EMS_baseport; //Get the EMS port!
	if (port >= NUMITEMS(EMS_pages)) return 0; //No EMS!
	EMS_pages[port] = value; //Set the page!
	return 1; //Give the value!
}

void initEMS(uint_32 memorysize)
{
	doneEMS(); //Make sure we're cleaned up first!
	EMS = (byte *)zalloc(memorysize, "EMS", getLock(LOCK_CPU));
	if (EMS) //Allocated?
	{
		EMS_size = memorysize; //We're allocated for this much!
		register_PORTIN(&readEMSIO);
		register_PORTOUT(&writeEMSIO);
		MMU_registerWriteHandler(&writeEMSMem, "EMS");
		MMU_registerReadHandler(&readEMSMem, "EMS");
		memset(&EMS_pages, 0, sizeof(EMS_pages)); //Initialise EMS pages to first page!
	}
}

void doneEMS()
{
	freez((void **)&EMS, EMS_size, "EMS"); //Free our memory!
	EMS_size = 0; //No size anymore!
}
