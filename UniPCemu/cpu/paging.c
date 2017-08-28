#include "headers/cpu/mmu.h" //MMU reqs!
#include "headers/cpu/cpu.h" //CPU reqs!
#include "headers/mmu/mmu_internals.h" //Internal transfer support!
#include "headers/mmu/mmuhandler.h" //MMU direct access support!
#include "headers/cpu/easyregs.h" //Easy register support!
#include "headers/support/log.h" //Logging support!
#include "headers/emu/debugger/debugger.h" //Debugger support!
#include "headers/cpu/protection.h" //Fault raising support!
#include "headers/cpu/cpu_execution.h" //Execution phase support!

extern byte EMU_RUNNING; //1 when paging can be applied!

//20-bit PDBR. Could also be CR3 in total?
#define PDBR CPU[activeCPU].registers->CR3
//#define PDBR ((CPU[activeCPU].registers->CR3>>12)&0xFFFFF)

byte is_paging()
{
	if (likely(CPU[activeCPU].registers)) //Gotten registers?
	{
		return ((getcpumode()!=CPU_MODE_REAL) && (CPU[activeCPU].registers->CR0&CR0_PG))?1:0; //Are we paging in protected mode!
	}
	return 0; //Not paging: we don't have registers!
}

//Present: 1 when below is used, 0 is invalid: not present (below not used/to be trusted).
#define PXE_P 0x00000001
//Write allowed? Else read-only.
#define PXE_RW 0x00000002
//1=User, 0=Supervisor only
#define PXE_US 0x00000004
//Write through
#define PXE_W 0x00000008
//Cache disabled
#define PDE_D 0x00000010
//Cache disable
#define PTE_C 0x00000010
//Accessed
#define PXE_A 0x00000020
//Page size (0 for 4KB, 1 for 4MB)
#define PDE_S 0x00000040
//Dirty: we've been written to!
#define PTE_D 0x00000040
//Global flag! Must be on PTE only (PDE is cleared always)
#define PTE_G 0x00000100
//Address mask/active mask(in the lookup table)
#define PXE_ADDRESSMASK 0xFFFFF000
#define PXE_ACTIVEMASK 0xFFF
//Address shift
#define PXE_ADDRESSSHIFT 12

byte getUserLevel(byte CPL)
{
	return (CPL==3)?1:0; //1=User, 0=Supervisor
}

void raisePF(uint_32 address, word flags)
{
	if (debugger_logging()) //Are we logging?
	{
		dolog("debugger","#PF fault(%08X,%08X)!",address,flags);
	}
	if (!(flags&1) && CPU[activeCPU].registers) //Not present?
	{
		CPU[activeCPU].registers->CR2 = address; //Fill CR2 with the address cause!
	}
	//Call interrupt!
	CPU_resetOP(); //Go back to the start of the instruction!
	/*
	if (CPU[activeCPU].have_oldESP && CPU[activeCPU].registers) //Returning the (E)SP to it's old value?
	{
		REG_ESP = CPU[activeCPU].oldESP; //Restore ESP to it's original value!
		CPU[activeCPU].have_oldESP = 0; //Don't have anything to restore anymore!
	}
	*/
	CPU_onResettingFault(); //Set the fault data!
	if (CPU_faultraised(EXCEPTION_PAGEFAULT)) //Fault raising exception!
	{
		CPU_executionphase_startinterrupt(EXCEPTION_PAGEFAULT,0,(int_64)flags); //Call IVT entry #13 decimal!
		//Execute the interrupt!
		CPU[activeCPU].faultraised = 1; //We have a fault raised, so don't raise any more!
	}
}

OPTINLINE byte verifyCPL(byte iswrite, byte userlevel, byte PDERW, byte PDEUS, byte PTERW, byte PTEUS) //userlevel=CPL or 0 (with special instructions LDT, GDT, TSS, IDT, ring-crossing CALL/INT)
{
	byte uslevel; //Combined US level! 0=Supervisor, 1=User
	byte rwlevel; //Combined RW level! 1=Writable, 0=Not writable
	if (PDEUS&&PTEUS) //User level?
	{
		uslevel = 1; //We're user!
		rwlevel = ((PDERW&&PTERW)?1:0); //Are we writable?
	}
	else //System? Allow read/write if supervisor only! Otherwise, fault!
	{
		uslevel = 0; //We're system!
		rwlevel = 1; //Ignore read/write!
	}
	if ((uslevel==0) && userlevel) //System access by user isn't allowed!
	{
		return 0; //Fault: system access by user!
	}
	if (userlevel && (rwlevel==0) && iswrite) //Write to read-only page for user level?
	{
		return 0; //Fault: read-only write by user!
	}
	return 1; //OK: verified!
}

int isvalidpage(uint_32 address, byte iswrite, byte CPL, byte isPrefetch) //Do we have paging without error? userlevel=CPL usually.
{
	word DIR, TABLE;
	byte PTEUPDATED = 0; //Not update!
	uint_32 PDE, PTE; //PDE/PTE entries currently used!
	if (!CPU[activeCPU].registers) return 0; //No registers available!
	DIR = (address>>22)&0x3FF; //The directory entry!
	TABLE = (address>>12)&0x3FF; //The table entry!
	
	byte effectiveUS;
	byte RW;
	RW = iswrite?1:0; //Are we trying to write?
	effectiveUS = getUserLevel(CPL); //Our effective user level!

	uint_32 temp;
	if (Paging_readTLB(address,RW,effectiveUS,RW,&temp)) //Cache hit not dirty? Don't check not dirty when writing(must be marked dirty, otherwise we won't handle non-dirty values below(and mark them dirty appropriately)).
	{
		return 1; //Valid!
	}
	if (Paging_readTLB(address,RW,effectiveUS,1,&temp)) //Cache hit dirty?
	{
		return 1; //Valid!
	}
	if (isPrefetch) return 0; //Stop the prefetch when not in the TLB!
	//Check PDE
	PDE = memory_directrdw(PDBR+(DIR<<2)); //Read the page directory entry!
	if (!(PDE&PXE_P)) //Not present?
	{
		raisePF(address,(RW<<1)|(effectiveUS<<2)); //Run a not present page fault!
		return 0; //We have an error, abort!
	}
	
	//Check PTE
	PTE = memory_directrdw(((PDE&PXE_ADDRESSMASK)>>PXE_ADDRESSSHIFT)+(TABLE<<2)); //Read the page table entry!
	if (!(PTE&PXE_P)) //Not present?
	{
		raisePF(address,(RW<<1)|(effectiveUS<<2)); //Run a not present page fault!
		return 0; //We have an error, abort!
	}

	if (!verifyCPL(RW,effectiveUS,((PDE&PXE_RW)>>1),((PDE&PXE_US)>>2),((PTE&PXE_RW)>>1),((PTE&PXE_US)>>2))) //Protection fault on combined flags?
	{
		raisePF(address,PXE_P|(RW<<1)|(effectiveUS<<2)); //Run a not present page fault!
		return 0; //We have an error, abort!		
	}
	if (!(PTE&PXE_A))
	{
		PTEUPDATED = 1; //Updated!
		PTE |= PXE_A; //Accessed!
	}
	if (iswrite) //Writing?
	{
		if (!(PTE&PTE_D))
		{
			PTEUPDATED = 1; //Updated!
		}
		PTE |= PTE_D; //Dirty!
	}
	if (!(PDE&PXE_A)) //Not accessed yet?
	{
		PDE |= PXE_A; //Accessed!
		memory_directwdw(PDBR+(DIR<<2),PDE); //Update in memory!
	}
	if (PTEUPDATED) //Updated?
	{
		memory_directwdw(((PDE&PXE_ADDRESSMASK)>>PXE_ADDRESSSHIFT)+(TABLE<<2),PTE); //Update in memory!
	}
	Paging_writeTLB(address,RW,effectiveUS,(PTE&PTE_D)?1:0,(PTE&PXE_ADDRESSMASK)); //Save the PTE 32-bit address in the TLB!
	return 1; //Valid!
}

byte CPU_Paging_checkPage(uint_32 address, byte readflags, byte CPL)
{
	return (isvalidpage(address,(readflags==0),CPL,(readflags&0x10))==0); //Are we an invalid page? We've raised an error! Bit4 is set during Prefetch operations!
}

uint_32 mappage(uint_32 address, byte iswrite, byte CPL) //Maps a page to real memory when needed!
{
	uint_32 result; //What address?
	if (!is_paging()) return address; //Direct address when not paging!
	byte effectiveUS;
	byte RW;
	RW = iswrite?1:0; //Are we trying to write?
	effectiveUS = getUserLevel(CPL); //Our effective user level!
	retrymapping: //Retry the mapping when not cached!
	if (Paging_readTLB(address,RW,effectiveUS,RW,&result)) //Cache hit? Don't check not dirty when writing.
	{
		return (result|(address&PXE_ACTIVEMASK)); //Give the actual address from the TLB!
	}
	else if (Paging_readTLB(address,RW,effectiveUS,1,&result)) //Cache hit?
	{
		return (result|(address&PXE_ACTIVEMASK)); //Give the actual address from the TLB!
	}
	else
	{
		if (isvalidpage(address,iswrite,CPL,0))
		{
			goto retrymapping;
		}
	}
	return address; //Untranslated!
}

byte Paging_TLBSet(uint_32 logicaladdress)
{
	return ((logicaladdress&0x30000000)>>28); //The set is determined by the upper 2 bits of the entry, the memory block!
}

byte Paging_oldestTLB(byte set) //Find a TLB to be used/overwritten!
{
	byte x,oldest;
	for (x=0;x<8;++x) //Check all TLBs!
	{
		if ((CPU[activeCPU].Paging_TLB.TLB[set][x].TAG&1)==0) //Unused?
		{
			return x; //Give the unused entry!
		}
		if (CPU[activeCPU].Paging_TLB.TLB[set][x].age==7) //Oldest?
		{
			oldest = x; //Oldest entry to give if nothing is available!
		}
	}
	return oldest; //Give the oldest entry!
}

uint_32 Paging_generateTAG(uint_32 logicaladdress, byte RW, byte US, byte Dirty)
{
	return ((logicaladdress&0xFFFFF000)|(Dirty<<3)|(RW<<2)|(US<<1)|1); //The used TAG!
}

byte Paging_matchTLBaddress(uint_32 logicaladdress, uint_32 TAG)
{
	return (((logicaladdress&0xFFFFF000)|1)==((TAG&0xFFFFF000)|(TAG&1))); //The used TAG matches on address and availability only! Ignore US/RW!
}

typedef struct
{
	sbyte age; //The age to sort!
	byte entry; //Entry index into the entries!
} AGEENTRY;

int compareageentry( const void* a, const void* b)
{
     AGEENTRY *int_a = ( (AGEENTRY*) a );
     AGEENTRY *int_b = ( (AGEENTRY*) b );

     if ( int_a->age == int_b->age ) return 0;
     else if ( int_a->age < int_b->age ) return -1;
     else return 1;
}
void Paging_refreshAges(byte TLB_set, byte newestentry) //Refresh the ages, with the entry specified as newest!
{
	AGEENTRY sortarray[8];
	byte x,y;
	x = 0;
	//Age bit 3 is assigned to become 8+(invalid/unused, which is moved to the end with value assigned 0)!
	for (x=0;x<8;++x)
	{
		sortarray[x].age = (((CPU[activeCPU].Paging_TLB.TLB[TLB_set][x].TAG&1)^1)<<3)|(CPU[activeCPU].Paging_TLB.TLB[TLB_set][x].age); //Move unused entries to the end!
		sortarray[x].entry = x; //What entry are we?
	}
	qsort(&sortarray,8,sizeof(AGEENTRY),&compareageentry); //Sort the entries!
	y = 0; //Initialize the age to apply!
	for (x=0;x<8;++x) //Apply the new order!
	{
		CPU[activeCPU].Paging_TLB.TLB[TLB_set][sortarray[x].entry].age = (y>>(sortarray[x].age&8)); //Generated age or unused age(0)!
		if ((sortarray[x].age&8)==0) ++y; //Next when valid entry!
	}
}

void Paging_writeTLB(uint_32 logicaladdress, byte RW, byte US, byte Dirty, uint_32 result)
{
	byte TLB_set;
	TLB_set = Paging_TLBSet(logicaladdress); //Determine the set to use!
	uint_32 TAG;
	TAG = Paging_generateTAG(logicaladdress,RW,US,Dirty); //Generate a TAG!
	byte entry;
	entry = Paging_oldestTLB(TLB_set); //Get the oldest/unused TLB!
	CPU[activeCPU].Paging_TLB.TLB[TLB_set][entry].age = -1; //Clear the age: w�re the new last used!
	CPU[activeCPU].Paging_TLB.TLB[TLB_set][entry].data = result; //The result for the lookup!
	CPU[activeCPU].Paging_TLB.TLB[TLB_set][entry].TAG = TAG; //The TAG to find it by!
	Paging_refreshAges(TLB_set,entry); //Refresh the ages!
}

byte Paging_readTLB(uint_32 logicaladdress, byte RW, byte US, byte Dirty, uint_32 *result)
{
	byte TLB_set;
	TLB_set = Paging_TLBSet(logicaladdress); //Determine the set to use!
	uint_32 TAG;
	TAG = Paging_generateTAG(logicaladdress,RW,US,Dirty); //Generate a TAG!
	byte entry;
	for (entry=0;entry<8;++entry) //Check all entries!
	{
		if (unlikely(CPU[activeCPU].Paging_TLB.TLB[TLB_set][entry].TAG==TAG)) //Found?
		{
			*result = CPU[activeCPU].Paging_TLB.TLB[TLB_set][entry].data; //Give the stored data!
			if (unlikely(CPU[activeCPU].Paging_TLB.TLB[TLB_set][entry].age)) //Not the newest age(which is always 0)?
			{
				CPU[activeCPU].Paging_TLB.TLB[TLB_set][entry].age = -1; //Clear the age: we're the new last used!
				Paging_refreshAges(TLB_set,entry); //Refresh the ages!
			}
			return 1; //Found!
		}
	}
	return 0; //Not found!
}

void Paging_Invalidate(uint_32 logicaladdress) //Invalidate a single address!
{
	byte TLB_set;
	TLB_set = Paging_TLBSet(logicaladdress); //Determine the set to use!
	byte entry;
	for (entry=0;entry<8;++entry) //Check all entries!
	{
		if (Paging_matchTLBaddress(logicaladdress,CPU[activeCPU].Paging_TLB.TLB[TLB_set][entry].TAG)) //Matched?
		{
			CPU[activeCPU].Paging_TLB.TLB[TLB_set][entry].TAG = 0; //Clear the entry to unused!
		}
	}	
}

void Paging_clearTLB()
{
	memset(&CPU[activeCPU].Paging_TLB,0,sizeof(CPU[activeCPU].Paging_TLB)); //Reset fully and clear the TLB!
}

void Paging_initTLB()
{
	Paging_clearTLB(); //Clear the TLB!
}
