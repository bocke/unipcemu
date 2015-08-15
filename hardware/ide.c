//ATA-1 harddisk emulation

#include "headers/types.h" //Basic types!
#include "headers/bios/io.h" //I/O support!
#include "headers/hardware/ports.h" //I/O port support!

//Primary hard disk IRQ!
#define ATA_IRQ 14

word portaddress = 0x300;

extern byte singlestep; //Enable single stepping when called?

struct
{
	word datapos; //Data position?
	byte data[512]; //Full sector data!
	word resultpos; //Result position?
	word resultsize; //Result size?
	byte result[512]; //Full result data!
	byte command;
	byte commandstatus; //Do we have a command?
	struct
	{
		union
		{
			struct
			{
				byte noaddressmark : 1;
				byte track0notfound : 1;
				byte commandaborted : 1;
				byte nomedia : 1;
				byte idmarknotfound : 1;
				byte nomedia2 : 1;
				byte uncorrectabledata : 1;
				byte badsector : 1;
			};
			byte data;
		} ERRORREGISTER;
		union
		{
			struct
			{
				byte error : 1;
				byte inlex : 1;
				byte correcteddata : 1;
				byte datarequestready : 1;
				byte driveseekcomplete : 1;
				byte drivewritefault : 1;
				byte driveready : 1;
				byte busy : 1;
			};
			byte data;
		} STATUSREGISTER;

		struct
		{
			union
			{
				struct
				{
					byte sectornumber; //LBA bits 0-7!
					byte cylinderhigh; //LBA bits 8-15!
					byte cylinderlow; //LBA bits 16-23!
					union
					{
						byte drivehead; //LBA 24-27!
						struct
						{
							byte head : 4; //What head?
							byte slavedrive : 1; //What drive?
							byte always1_1 : 1;
							byte LBAMode_2 : 1; //LBA mode?
							byte always1_2 : 1;
						};
						struct
						{
							byte LBAhigh : 6; //High 6 bits!
							byte LBAMode : 1; //LBA mode?
							byte always1_3 : 1;
						};
					};
				};
				uint_32 LBA; //LBA address in LBA mode (28 bits value)!
			};
			byte features;
			byte sectorcount;
		} PARAMETERS;
		word driveparams[0x100]; //All drive parameters for a drive!
	} Drive[2]; //Two drives!

	byte activedrive; //What drive are we currently?

	union
	{
		struct
		{
			byte Reserved1 : 1;
			byte DiskInitialisationDisable : 1;
			byte DiskResetEnable : 1;
			byte HeadSelect3Enable : 1;
			byte Unused : 4;
		};
		byte data;
	} port3f6;
	union
	{
		struct
		{
			byte Drive0Select : 1;
			byte Drive1Select : 1;
			byte HeadSelect0 : 1;
			byte HeadSelect1 : 1;
			byte HeadSelect2 : 1;
			byte HeadSelect3 : 1;
			byte WriteGate : 1;
			byte Unused : 1;
		};
		byte data;
	} port3f7;
	byte DMAPending; //DMA pending?
	byte TC; //Terminal count occurred in DMA transfer?
} ATA;

word get_cylinders(uint_64 disk_size)
{
	return floor(disk_size / (63 * 16)); //How many cylinders!
}

word get_heads(uint_64 disk_size)
{
	return 16;
}

word get_SPT(uint_64 disk_size)
{
	return 63;
}

byte ATA_activeDrive()
{
	return ATA.activedrive; //Give the drive or 0xFF if invalid!
}

byte ATA_resultIN()
{
	byte result;
	switch (ATA.command)
	{
	case 0xEC: //Identify?
		result = ATA.result[ATA.resultpos++]; //Read the result byte!
		if (ATA.resultpos == ATA.resultsize) //Fully read?
		{
			ATA.commandstatus = 0; //Reset command!
		}
		return result; //Give the result byte!
		break;
	default: //Unknown?
		break;
	}
	return 0; //Unknown data!
}

byte ATA_dataIN() //Byte read from data!
{
	switch (ATA.command) //What command?
	{
	default: //Unknown?
		break;
	}
	return 0; //Unknown data!
}

void ATA_dataOUT(byte data) //Byte written to data!
{
	switch (ATA.command) //What command?
	{
	default: //Unknown?
		break;
	}
}

void ATA_executeCommand(byte command) //Execute a command!
{
	switch (command) //What command?
	{
	case 0x91: //Initialise device parameters?
		ATA.commandstatus = 0; //Requesting command again!
		break;
	case 0xEC: //Identify drive?
		ATA.command = 0xEC; //We're running this command!
		memcpy(&ATA.result, &ATA.Drive[ATA_activeDrive()].driveparams, sizeof(ATA.Drive[ATA_activeDrive()].driveparams)); //Set drive parameters currently set!
		//Finish up!
		ATA.resultpos = 0; //Initialise data position for the result!
		ATA.resultsize = sizeof(ATA.Drive[ATA_activeDrive()].driveparams); //512 byte result!
		ATA.commandstatus = 3; //We're requesting data to be read!
		doirq(ATA_IRQ); //Execute the IRQ!
		break;
	default: //Unknown command?
		ATA.command = 0; //No command!
		ATA.Drive[ATA_activeDrive()].ERRORREGISTER.data = 0; //Clear the error register!
		ATA.Drive[ATA_activeDrive()].ERRORREGISTER.commandaborted = 1; //Aborted!
		ATA.commandstatus = 0xFF; //Move to error mode!
		break;
	}
}

void ATA_updateStatus()
{
	switch (ATA.commandstatus) //What command status?
	{
	case 0: //Ready for command?
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.busy = 0; //Not busy!
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.driveready = 1; //We're ready to process data and spun down!
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.error = 0; //No error!
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.datarequestready = 0; //Requesting data!
		break;
	case 1: //Transferring data IN?
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.busy = 1; //Busy!
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.datarequestready = 1;
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.driveready = 1; //We're ready to process data!
		break;
	case 2: //Transferring data OUT?
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.busy = 1; //Busy!
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.datarequestready = 1;
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.driveready = 1; //We're ready to process data!
		break;
	case 3: //Transferring result?
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.busy = 0; //Not busy!
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.datarequestready = 1; //Requesting data!
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.driveready = 1; //We're ready to process data!
		break;
	default: //Unknown?
	case 0xFF: //Error?
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.error = 1; //Error!
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.busy = 0; //Not busy!
		ATA.Drive[ATA_activeDrive()].STATUSREGISTER.driveready = 1; //We're ready to process data!
		break;
	}
}

byte outATA(word port, byte value)
{
	if ((port & 0xFFF8) != portaddress)
	{
		if ((port == 0x3F6) || (port == 0x3F7)) goto port3_write;
		return 0; //Not our port?
	}
	switch (port & 7) //What port?
	{
	case 0: //DATA?
		switch (ATA.commandstatus) //Current status?
		{
		case 2: //DATA OUT?
			ATA_dataOUT(value); //Read data!
			break;
		default: //Unknown status?
			break;
		}
		return 1;
		break;
	case 1: //Features?
		switch (value&1) //PIO vs DMA!
		{
		case 0: //PIO?
			ATA.Drive[ATA_activeDrive()].PARAMETERS.features &= ~1; //Use the set mode!
			break;
		case 1: //DMA?
			//Ignore: not supported yet!
			break;
		}
		return 1; //OK!
		break;
	case 2: //Sector count?
		ATA.Drive[ATA_activeDrive()].PARAMETERS.sectorcount = value; //Set sector count!
		return 1; //OK!
		break;
	case 3: //Sector number?
		ATA.Drive[ATA_activeDrive()].PARAMETERS.sectornumber = value; //Set sector number!
		return 1; //OK!
		break;
	case 4: //Cylinder low?
		ATA.Drive[ATA_activeDrive()].PARAMETERS.cylinderlow = value; //Set cylinder low!
		return 1; //OK!
		break;
	case 5: //Cylinder high?
		ATA.Drive[ATA_activeDrive()].PARAMETERS.cylinderhigh = value; //Set cylinder high!
		return 1; //OK!
		break;
	case 6: //Drive/head?
		ATA.activedrive = (value >> 4) & 1; //The active drive!
		ATA.Drive[ATA_activeDrive()].PARAMETERS.drivehead = value; //Set drive head!
		return 1; //OK!
		break;
	case 7: //Command?
		ATA_executeCommand(value); //Execute a command!
		return 1; //OK!
		break;
	}
	return 0; //Safety!
port3_write: //Special port #3?
	switch (port) //What port?
	{
	case 0x3F6: //Fixed disk controller data register?
		ATA.port3f6.data = (value & 0xF); //Select information!
		return 1; //OK!
		break;
	case 0x3F7: //Drive 0 select?
		ATA.port3f7.data = (value & 0x7F); //Select the data used!
		return 1; //OK!
		break;
	}
	return 0; //Unsupported!
}

byte inATA(word port, byte *result)
{
	if ((port & 0xFFF8) != portaddress)
	{
		if ((port == 0x3F6) || (port == 0x3F7)) goto port3_read;
		return 0; //Not our port?
	}
	switch (port & 7) //What port?
	{
	case 0: //DATA?
		switch (ATA.commandstatus) //Current status?
		{
		case 1: //DATA IN?
			*result = ATA_dataIN(); //Read data!
			break;
		case 3: //Result IN?
			*result = ATA_resultIN(); //Read result!
			break;
		default: //Unknown status?
			*result = 0; //Unsupported for now!
			break;
		}
		return 1; //Unsupported yet!
		break;
	case 1: //Error register?
		*result = ATA.Drive[ATA_activeDrive()].ERRORREGISTER.data; //Error register!
		return 1;
		break;
	case 2: //Sector count?
		*result = ATA.Drive[ATA_activeDrive()].PARAMETERS.sectorcount; //Get sector count!
		return 1;
		break;
	case 3: //Sector number?
		*result = ATA.Drive[ATA_activeDrive()].PARAMETERS.sectornumber; //Get sector number!
		return 1; //OK!
		break;
	case 4: //Cylinder low?
		*result = ATA.Drive[ATA_activeDrive()].PARAMETERS.cylinderlow; //Get cylinder low!
		return 1; //OK!
		break;
	case 5: //Cylinder high?
		*result = ATA.Drive[ATA_activeDrive()].PARAMETERS.cylinderhigh; //Get cylinder high!
		return 1; //OK!
		break;
	case 6: //Drive/head?
		*result = ATA.Drive[ATA_activeDrive()].PARAMETERS.drivehead; //Get drive/head!
		return 1; //OK!
		break;
	case 7: //Status?
		ATA_updateStatus(); //Update the status register if needed!
		*result = ATA.Drive[ATA_activeDrive()].STATUSREGISTER.data; //Get status!
		return 1; //OK!
		break;
	}
	return 0; //Unsupported!
port3_read: //Special port #3?
	switch (port) //What port?
	{
	case 0x3F6: //Fixed disk controller data register?
		*result = ATA.port3f6.data; //Select information!
		return 1; //OK!
		break;
	case 0x3F7: //Drive 0 select?
		*result = ATA.port3f7.data; //Select the data used!
		return 1; //OK!
		break;
	}
	return 0; //Unsupported!
}

void HDD_DiskChanged(int disk)
{
	uint_64 disk_size;
	switch (disk)
	{
	case HDD0: //HDD0 changed?
	case HDD1: //HDD1 changed?
		if (has_drive(disk)) //Do we even have this drive?
		{
			disk_size = disksize(disk); //Get the disk's size!
			disk_size >>= 9; //Get the disk size in sectors!
			disk = (disk == HDD0) ? 0 : 1; //What disk are we?
			ATA.Drive[disk].driveparams[0] = 0x02 | 0x40; //Hard sectored, Fixed drive!
			ATA.Drive[disk].driveparams[1] = ATA.Drive[disk].driveparams[54] = get_cylinders(disk_size); //1=Number of cylinders
			ATA.Drive[disk].driveparams[2] = ATA.Drive[disk].driveparams[55] = get_heads(disk_size); //3=Number of heads
			ATA.Drive[disk].driveparams[6] = ATA.Drive[disk].driveparams[56] = get_SPT(disk_size); //6=Sectors per track
			ATA.Drive[disk].driveparams[21] = 1; //512 byte buffer!
			ATA.Drive[disk].driveparams[49] = 0x200; //LBA supported, DMA unsupported!
			ATA.Drive[disk].driveparams[60] = (disk_size & 0xFFFF); //Number of addressable sectors, low word!
			ATA.Drive[disk].driveparams[61] = (disk_size >> 16); //Number of addressable sectors, high word!
		}
		else //Drive not inserted?
		{
			memset(ATA.Drive[disk].driveparams, 0, sizeof(ATA.Drive[disk].driveparams)); //Clear the information on the drive: it's non-existant!
		}
		break;
	default: //Unknown?
		break;
	}
}

void initATA()
{
	memset(&ATA, 0, sizeof(ATA)); //Initialise our data!
	//We don't register a disk change handler, because ATA doesn't change disks when running!
	register_PORTIN(&inATA);
	register_PORTOUT(&outATA);
	//We don't implement DMA: this is done by our own DMA controller!
	register_DISKCHANGE(HDD0, &HDD_DiskChanged);
	register_DISKCHANGE(HDD1, &HDD_DiskChanged);
	HDD_DiskChanged(HDD0); //Init HDD0!
	HDD_DiskChanged(HDD1); //Init HDD1!
}