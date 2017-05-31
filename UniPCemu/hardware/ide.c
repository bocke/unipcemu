//ATA-1 harddisk emulation

#include "headers/types.h" //Basic types!
#include "headers/basicio/io.h" //I/O support!
#include "headers/hardware/ports.h" //I/O port support!
#include "headers/hardware/pci.h" //PCI support!
#include "headers/hardware/pic.h" //PIC support!
#include "headers/support/log.h" //Logging support for debugging!

//#define ATA_LOG

//Timeout for a reset! We're up to 3us!
#define ATA_RESET_TIMEOUT 2000.0
#define ATA_DRIVESELECT_TIMEOUT 50000.0

//Hard disk IRQ!
#define ATA_PRIMARYIRQ_AT 0x0E
#define ATA_SECONDARYIRQ_AT 0x0F
#define ATA_PRIMARYIRQ_XT 0x15
#define ATA_SECONDARYIRQ_XT 0x25

//Bits 6-7 of byte 2 of the Mode Sense command
//Current values
#define CDROM_PAGECONTROL_CURRENT 0
//Changable values
#define CDROM_PAGECONTROL_CHANGEABLE 1
//Default values
#define CDROM_PAGECONTROL_DEFAULT 2
//Saved values
#define CDROM_PAGECONTROL_SAVED 3

PCI_CONFIG PCI_IDE;

struct
{
	byte longop; //Long operation instead of a normal one?
	uint_32 datapos; //Data position?
	uint_32 datablock; //How large is a data block to be transferred?
	uint_32 datasize; //Data size in blocks to transfer?
	byte data[0x10000]; //Full sector data, large enough to buffer anything we throw at it (normal buffering)! Up to 10000 
	byte command;
	byte commandstatus; //Do we have a command?
	struct
	{
		byte ATAPI_processingPACKET; //Are we processing a packet or data for the ATAPI device?
		double ATAPI_PendingExecuteCommand; //How much time is left pending?
		byte ATAPI_PACKET[12]; //Full ATAPI packet!
		byte ATAPI_ModeData[0x10000]; //All possible mode selection data, that's specified!
		byte ATAPI_DefaultModeData[0x10000]; //All possible default mode selection data, that's specified!
		byte ATAPI_SupportedMask[0x10000]; //Supported mask bits for all saved values! 0=Not supported, 1=Supported!
		byte ERRORREGISTER;
		byte STATUSREGISTER;

		byte SensePacket[0x10]; //Data of a request sense packet.

		struct
		{
			union
			{
				struct
				{
					byte sectornumber; //LBA bits 0-7!
					byte cylinderhigh; //LBA bits 8-15!
					byte cylinderlow; //LBA bits 16-23!
					byte drivehead; //LBA 24-27!
				};
				uint_32 LBA; //LBA address in LBA mode (28 bits value)!
			};
			byte features;
			byte sectorcount;
		} PARAMETERS;
		word driveparams[0x100]; //All drive parameters for a drive!
		uint_32 current_LBA_address; //Current LBA address!
		byte Enable8BitTransfers; //Enable 8-bit transfers?
		byte preventMediumRemoval; //Are we preventing medium removal for removable disks(CD-ROM)?
		byte isSpinning; //Are we spinning the disc?
		uint_32 ATAPI_LBA; //ATAPI LBA storage!
	} Drive[2]; //Two drives!

	byte DriveControlRegister;
	byte DriveAddressRegister;

	byte activedrive; //What drive are we currently?
	byte DMAPending; //DMA pending?
	byte TC; //Terminal count occurred in DMA transfer?
	double resetTiming;
	double driveselectTiming;
} ATA[2]; //Two channels of ATA drives!

//Drive/Head register
#define ATA_DRIVEHEAD_HEADR(channel,drive) (ATA[channel].Drive[drive].PARAMETERS.drivehead&0xF)
#define ATA_DRIVEHEAD_HEADW(channel,drive,val) ATA[channel].Drive[drive].PARAMETERS.drivehead=((ATA[channel].Drive[drive].PARAMETERS.drivehead&~0xF)|(val&0xF))
#define ATA_DRIVEHEAD_SLAVEDRIVER(channel,drive) ((ATA[channel].Drive[drive].PARAMETERS.drivehead>>4)&1)
#define ATA_DRIVEHEAD_LBAMODE_2R(channel,drive) ((ATA[channel].Drive[drive].PARAMETERS.drivehead>>6)&1)
#define ATA_DRIVEHEAD_LBAMODE_2W(channel,drive,val) ATA[channel].Drive[drive].PARAMETERS.drivehead=((ATA[channel].Drive[drive].PARAMETERS.drivehead&~0x40)|((val&1)<6))
#define ATA_DRIVEHEAD_LBAHIGHR(channel,drive) (ATA[channel].Drive[drive].PARAMETERS.drivehead&0x3F)
#define ATA_DRIVEHEAD_LBAHIGHW(channel,drive,val) ATA[channel].Drive[drive].PARAMETERS.drivehead=((ATA[channel].Drive[drive].PARAMETERS.drivehead&~0x3F)|(val&0x3F))
#define ATA_DRIVEHEAD_LBAMODER(channel,drive) ((ATA[channel].Drive[drive].PARAMETERS.drivehead>>6)&1)

//Drive Control Register
//nIEN: Disable interrupts when set or not the drive selected!
#define DRIVECONTROLREGISTER_NIENR(channel) ((ATA[channel].DriveControlRegister>>1)&1)
//Reset!
#define DRIVECONTROLREGISTER_SRSTR(channel) ((ATA[channel].DriveControlRegister>>2)&1)

//Status Register

//An error has occurred when 1!
#define ATA_STATUSREGISTER_ERRORR(channel,drive) (ATA[channel].Drive[drive].STATUSREGISTER&1)
//An error has occurred when 1!
#define ATA_STATUSREGISTER_ERRORW(channel,drive,val) ATA[channel].Drive[drive].STATUSREGISTER=((ATA[channel].Drive[drive].STATUSREGISTER&~1)|(val&1))
//Set once per disk revolution.
#define ATA_STATUSREGISTER_INDEXW(channel,drive,val) ATA[channel].Drive[drive].STATUSREGISTER=((ATA[channel].Drive[drive].STATUSREGISTER&~2)|((val&1)<<1))
//Data has been corrected.
#define ATA_STATUSREGISTER_CORRECTEDDATAW(channel,drive,val) ATA[channel].Drive[drive].STATUSREGISTER=((ATA[channel].Drive[drive].STATUSREGISTER&~4)|((val&1)<<2))
//Ready to transfer a word or byte of data between the host and the drive.
#define ATA_STATUSREGISTER_DATAREQUESTREADYW(channel,drive,val) ATA[channel].Drive[drive].STATUSREGISTER=((ATA[channel].Drive[drive].STATUSREGISTER&~8)|((val&1)<<3))
//Drive heads are settled on a track.
#define ATA_STATUSREGISTER_DRIVESEEKCOMPLETEW(channel,drive,val) ATA[channel].Drive[drive].STATUSREGISTER=((ATA[channel].Drive[drive].STATUSREGISTER&~0x10)|((val&1)<<4))
//Write fault status.
#define ATA_STATUSREGISTER_DRIVEWRITEFAULTW(channel,drive,val) ATA[channel].Drive[drive].STATUSREGISTER=((ATA[channel].Drive[drive].STATUSREGISTER&~0x20)|((val&1)<<5))
//Ready to accept a command?
#define ATA_STATUSREGISTER_DRIVEREADYW(channel,drive,val) ATA[channel].Drive[drive].STATUSREGISTER=((ATA[channel].Drive[drive].STATUSREGISTER&~0x40)|((val&1)<<6))
//The drive has access to the Command Block Registers.
#define ATA_STATUSREGISTER_BUSYW(channel,drive,val) ATA[channel].Drive[drive].STATUSREGISTER=((ATA[channel].Drive[drive].STATUSREGISTER&~0x80)|((val&1)<<7))


//Error Register
#define ATA_ERRORREGISTER_NOADDRESSMARKW(channel,drive,val) ATA[channel].Drive[drive].ERRORREGISTER=((ATA[channel].Drive[drive].ERRORREGISTER&~1)|(val&1))
#define ATA_ERRORREGISTER_TRACK0NOTFOUNDW(channel,drive,val) ATA[channel].Drive[drive].ERRORREGISTER=((ATA[channel].Drive[drive].ERRORREGISTER&~2)|((val&1)<<1))
#define ATA_ERRORREGISTER_COMMANDABORTEDW(channel,drive,val) ATA[channel].Drive[drive].ERRORREGISTER=((ATA[channel].Drive[drive].ERRORREGISTER&~4)|((val&1)<<2))
#define ATA_ERRORREGISTER_MEDIACHANGEREQUESTEDW(channel,drive,val) ATA[channel].Drive[drive].ERRORREGISTER=((ATA[channel].Drive[drive].ERRORREGISTER&~8)|((val&1)<<3))
#define ATA_ERRORREGISTER_IDMARKNOTFOUNDW(channel,drive,val) ATA[channel].Drive[drive].ERRORREGISTER=((ATA[channel].Drive[drive].ERRORREGISTER&~0x10)|((val&1)<<4))
#define ATA_ERRORREGISTER_MEDIACHANGEDW(channel,drive,val) ATA[channel].Drive[drive].ERRORREGISTER=((ATA[channel].Drive[drive].ERRORREGISTER&~0x20)|((val&1)<<5))
#define ATA_ERRORREGISTER_UNCORRECTABLEDATAW(channel,drive,val) ATA[channel].Drive[drive].ERRORREGISTER=((ATA[channel].Drive[drive].ERRORREGISTER&~0x40)|((val&1)<<6))
#define ATA_ERRORREGISTER_BADSECTORW(channel,drive,val) ATA[channel].Drive[drive].ERRORREGISTER=((ATA[channel].Drive[drive].ERRORREGISTER&~0x80)|((val&1)<<7))

//ATAPI Sense Packet

//0x70
#define ATAPI_SENSEPACKET_ERRORCODEW(channel,drive,val) ATA[channel].Drive[drive].SensePacket[0]=((ATA[channel].Drive[drive].SensePacket[0]&~0x7F)|(val&0x7F))
#define ATAPI_SENSEPACKET_VALIDW(channel,drive,val) ATA[channel].Drive[drive].SensePacket[0]=((ATA[channel].Drive[drive].SensePacket[0]&~0x80)|((val&1)<<7))
#define ATAPI_SENSEPACKET_RESERVED1W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[1]=val
#define ATAPI_SENSEPACKET_REVERVED2W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[2]=((ATA[channel].Drive[drive].SensePacket[2]&~0xF)|(val&0xF))
#define ATAPI_SENSEPACKET_SENSEKEYW(channel,drive,val) ATA[channel].Drive[drive].SensePacket[2]=((ATA[channel].Drive[drive].SensePacket[2]&~0xF0)|((val&0xF)<<4))
#define ATAPI_SENSEPACKET_INFORMATION0W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[3]=val
#define ATAPI_SENSEPACKET_INFORMATION1W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[4]=val
#define ATAPI_SENSEPACKET_INFORMATION2W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[5]=val
#define ATAPI_SENSEPACKET_INFORMATION3W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[6]=val
#define ATAPI_SENSEPACKET_ADDITIONALSENSELENGTHW(channel,drive,val) ATA[channel].Drive[drive].SensePacket[7]=val
#define ATAPI_SENSEPACKET_COMMANDSPECIFICINFORMATION0W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[8]=val
#define ATAPI_SENSEPACKET_COMMANDSPECIFICINFORMATION1W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[9]=val
#define ATAPI_SENSEPACKET_COMMANDSPECIFICINFORMATION2W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[0xA]=val
#define ATAPI_SENSEPACKET_COMMANDSPECIFICINFORMATION3W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[0xB]=val
#define ATAPI_SENSEPACKET_ADDITIONALSENSECODEW(channel,drive,val) ATA[channel].Drive[drive].SensePacket[0xC]=val
#define ATAPI_SENSEPACKET_RESERVED3_0W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[0xD]=val
#define ATAPI_SENSEPACKET_RESERVED3_1W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[0xE]=val
#define ATAPI_SENSEPACKET_RESERVED3_2W(channel,drive,val) ATA[channel].Drive[drive].SensePacket[0xF]=val

OPTINLINE byte ATA_activeDrive(byte channel)
{
	return ATA[channel].activedrive; //Give the drive or 0xFF if invalid!
}

OPTINLINE uint_32 read_LBA(byte channel)
{
	return (ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.LBA & 0xFFFFFFF); //Give the LBA register contents!
}

OPTINLINE uint_32 ATA_CHS2LBA(byte channel, byte slave, word cylinder, byte head, byte sector)
{
	return ((cylinder*ATA[channel].Drive[slave].driveparams[55]) + head)*ATA[channel].Drive[slave].driveparams[56] + sector - 1; //Give the LBA value!
}

OPTINLINE void ATA_LBA2CHS(byte channel, byte slave, uint_32 LBA, word *cylinder, byte *head, byte *sector)
{
	uint_32 temp;
	temp = (ATA[channel].Drive[slave].driveparams[55] * ATA[channel].Drive[slave].driveparams[56]); //Sectors per cylinder!
	*cylinder = (word)(LBA / temp); //Cylinder!
	LBA -= *cylinder*temp; //Decrease LBA to get heads&sectors!
	temp = ATA[channel].Drive[slave].driveparams[56]; //SPT!
	*head = (LBA / temp) & 0xF; //The head!
	LBA -= *head*temp; //Decrease LBA to get sectors!
	*sector = ((LBA+1) & 0xFF); //The sector!
}

int ATA_Drives[2][2]; //All ATA mounted drives to disk conversion!
byte ATA_DrivesReverse[4][2]; //All Drive to ATA mounted drives conversion!

extern byte is_XT; //Are we emulating a XT architecture?

OPTINLINE void ATA_IRQ(byte channel, byte slave)
{
	if ((!DRIVECONTROLREGISTER_NIENR(channel)) && (!DRIVECONTROLREGISTER_SRSTR(channel)) && (ATA_activeDrive(channel)==slave)) //Allow interrupts?
	{
		if (is_XT)
		{
			switch (channel)
			{
			case 0: //Primary channel?
				raiseirq(ATA_PRIMARYIRQ_XT); //Execute the IRQ!
				break;
			case 1:
				raiseirq(ATA_SECONDARYIRQ_XT); //Execute the IRQ!
				break;
			default: //Unknown channel?
				break;
			}
		}
		else
		{
			switch (channel)
			{
			case 0: //Primary channel?
				raiseirq(ATA_PRIMARYIRQ_AT); //Execute the IRQ!
				break;
			case 1:
				raiseirq(ATA_SECONDARYIRQ_AT); //Execute the IRQ!
				break;
			default: //Unknown channel?
				break;
			}
		}
	}
}

OPTINLINE void ATA_removeIRQ(byte channel, byte slave)
{
	if (is_XT)
	{
		//Always allow removing an IRQ if it's raised! This doesn't depend on any flags set in registers!
		switch (channel)
		{
		case 0: //Primary channel?
			lowerirq(ATA_PRIMARYIRQ_XT); //Execute the IRQ!
			acnowledgeIRQrequest(ATA_PRIMARYIRQ_XT); //Acnowledge!
			break;
		case 1:
			lowerirq(ATA_SECONDARYIRQ_XT); //Execute the IRQ!
			acnowledgeIRQrequest(ATA_SECONDARYIRQ_XT); //Acnowledge!
			break;
		default: //Unknown channel?
			break;
		}
	}
	else
	{
		//Always allow removing an IRQ if it's raised! This doesn't depend on any flags set in registers!
		switch (channel)
		{
		case 0: //Primary channel?
			lowerirq(ATA_PRIMARYIRQ_AT); //Execute the IRQ!
			acnowledgeIRQrequest(ATA_PRIMARYIRQ_AT); //Acnowledge!
			break;
		case 1:
			lowerirq(ATA_SECONDARYIRQ_AT); //Execute the IRQ!
			acnowledgeIRQrequest(ATA_SECONDARYIRQ_AT); //Acnowledge!
			break;
		default: //Unknown channel?
			break;
		}
	}
}

struct
{
	double ATA_tickstiming;
	double ATA_tickstimeout; //How big a timeout are we talking about?
	byte type; //Type of timer!
} IRQtimer[4]; //IRQ timer!

void cleanATA()
{
}

void ATAPI_executeCommand(byte channel, byte drive); //Prototype for ATAPI execute Command!

void updateATA(double timepassed) //ATA timing!
{
	if (timepassed) //Anything passed?
	{
		/*
		int i;
		for (i = 0;i < 4;i++) //Process all timers!
		{
			if (IRQtimer[i].ATA_tickstimeout) //Ticking?
			{
				IRQtimer[i].ATA_tickstiming += timepassed; //We've passed some!
				if (IRQtimer[i].ATA_tickstiming >= IRQtimer[i].ATA_tickstimeout) //Expired?
				{
					IRQtimer[i].ATA_tickstimeout = 0; //Finished!
					ATA_IRQ(i & 2, i & 1); //Do an IRQ from the source!
					byte drive = (i & 1); //Drive!
					byte channel = ((i & 2) >> 1); //Channel!
					switch (ATA[channel].commandstatus)
					{
					case 3: //Waiting for completion of a command?
						switch (ATA[channel].command) //What command are we executing?
						{
						case 0x10:
						case 0x11:
						case 0x12:
						case 0x13:
						case 0x14:
						case 0x15:
						case 0x16:
						case 0x17:
						case 0x18:
						case 0x19:
						case 0x1A:
						case 0x1B:
						case 0x1C:
						case 0x1D:
						case 0x1E:
						case 0x1F: //Recalibrate?
							break;
						case 0x70:
						case 0x71:
						case 0x72:
						case 0x73:
						case 0x74:
						case 0x75:
						case 0x76:
						case 0x77:
						case 0x78:
						case 0x79:
						case 0x7A:
						case 0x7B:
						case 0x7C:
						case 0x7D:
						case 0x7E:
						case 0x7F: //Seek?
							break;
						} //Unused atm!
					}
				}
			}
		}*/ //Not used atm!

		//Handle ATA reset timing!
		if (ATA[0].resetTiming) //Timing reset?
		{
			ATA[0].resetTiming -= timepassed; //Time until timeout!
			if (ATA[0].resetTiming<=0.0) //Timeout?
			{
				ATA[0].resetTiming = 0.0; //Timer finished!
				ATA[0].commandstatus = 0; //We're ready now!
			}
		}
		if (ATA[1].resetTiming) //Timing reset?
		{
			ATA[1].resetTiming -= timepassed; //Time until timeout!
			if (ATA[1].resetTiming<=0.0) //Timeout?
			{
				ATA[1].resetTiming = 0.0; //Timer finished!
				ATA[1].commandstatus = 0; //We're ready now!
			}
		}

		//Handle ATA drive select timing!
		if (ATA[0].driveselectTiming) //Timing driveselect?
		{
			ATA[0].driveselectTiming -= timepassed; //Time until timeout!
			if (ATA[0].driveselectTiming<=0.0) //Timeout?
			{
				ATA[0].driveselectTiming = 0.0; //Timer finished!
			}
		}
		if (ATA[1].driveselectTiming) //Timing driveselect?
		{
			ATA[1].driveselectTiming -= timepassed; //Time until timeout!
			if (ATA[1].driveselectTiming<=0.0) //Timeout?
			{
				ATA[1].driveselectTiming = 0.0; //Timer finished!
			}
		}

		//Handle ATAPI execute command delay!
		if (ATA[0].Drive[0].ATAPI_PendingExecuteCommand) //Pending execute command?
		{
			ATA[0].Drive[0].ATAPI_PendingExecuteCommand -= timepassed; //Time until finished!
			if (ATA[0].Drive[0].ATAPI_PendingExecuteCommand<=0.0) //Finished?
			{
				ATA[0].Drive[0].ATAPI_PendingExecuteCommand = 0.0; //Timer finished!
				ATAPI_executeCommand(0,0); //Execute the command!
			}
		}
		if (ATA[0].Drive[1].ATAPI_PendingExecuteCommand) //Pending execute command?
		{
			ATA[0].Drive[1].ATAPI_PendingExecuteCommand -= timepassed; //Time until finished!
			if (ATA[0].Drive[1].ATAPI_PendingExecuteCommand<=0.0) //Finished?
			{
				ATA[0].Drive[1].ATAPI_PendingExecuteCommand = 0.0; //Timer finished!
				ATAPI_executeCommand(0,1); //Execute the command!
			}
		}
		if (ATA[1].Drive[0].ATAPI_PendingExecuteCommand) //Pending execute command?
		{
			ATA[1].Drive[0].ATAPI_PendingExecuteCommand -= timepassed; //Time until finished!
			if (ATA[1].Drive[0].ATAPI_PendingExecuteCommand<=0.0) //Finished?
			{
				ATA[1].Drive[0].ATAPI_PendingExecuteCommand = 0.0; //Timer finished!
				ATAPI_executeCommand(1,0); //Execute the command!
			}
		}
		if (ATA[1].Drive[1].ATAPI_PendingExecuteCommand) //Pending execute command?
		{
			ATA[1].Drive[1].ATAPI_PendingExecuteCommand -= timepassed; //Time until finished!
			if (ATA[1].Drive[1].ATAPI_PendingExecuteCommand<=0.0) //Finished?
			{
				ATA[1].Drive[1].ATAPI_PendingExecuteCommand = 0.0; //Timer finished!
				ATAPI_executeCommand(1,1); //Execute the command!
			}
		}
	}
}

OPTINLINE uint_32 getPORTaddress(byte channel)
{
	switch (channel)
	{
	case 0: //First?
		return (PCI_IDE.BAR[0] > 1) ? PCI_IDE.BAR[0] : 0x1F0; //Give the BAR!
		break;
	case 1: //Second?
		return (PCI_IDE.BAR[2] > 1) ? PCI_IDE.BAR[2] : 0x170; //Give the BAR!
		break;
	default:
		return ~0; //Error!
	}
}

OPTINLINE uint_32 getControlPORTaddress(byte channel)
{
	switch (channel)
	{
	case 0: //First?
		return (PCI_IDE.BAR[1] > 1) ? PCI_IDE.BAR[1]+2 : 0x3F6; //Give the BAR!
		break;
	case 1: //Second?
		return (PCI_IDE.BAR[3] > 1) ? PCI_IDE.BAR[3]+2 : 0x376; //Give the BAR!
		break;
	default:
		return ~0; //Error!
	}
}

void ATA_updateCapacity(byte channel, byte slave)
{
	uint_32 sectors;
	sectors = ATA[channel].Drive[slave].driveparams[54]; //Current cylinders!
	sectors *= ATA[channel].Drive[slave].driveparams[55]; //Current heads!
	sectors *= ATA[channel].Drive[slave].driveparams[56]; //Current sectors per track!
	ATA[channel].Drive[slave].driveparams[57] = (word)(sectors&0xFFFF);
	sectors >>= 16;
	ATA[channel].Drive[slave].driveparams[58] = (word)(sectors&0xFFFF);
}

word get_cylinders(uint_64 disk_size)
{
	uint_32 cylinders=0;
	cylinders = (uint_32)(disk_size / (63 * 16)); //How many cylinders!
	return (cylinders>=0x3FFF)?0x3FFF:cylinders; //Give the maximum amount of cylinders allowed!
}

OPTINLINE word get_heads(uint_64 disk_size)
{
	return 16;
}

OPTINLINE word get_SPT(uint_64 disk_size)
{
	return 63;
}

OPTINLINE void ATA_increasesector(byte channel) //Increase the current sector to the next sector!
{
	++ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address; //Increase the current sector!
}

OPTINLINE void ATA_updatesector(byte channel) //Update the current sector!
{
	word cylinder;
	byte head, sector;
	if (ATA_DRIVEHEAD_LBAMODER(channel,ATA_activeDrive(channel))) //LBA mode?
	{
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.LBA &= ~0xFFFFFFF; //Clear the LBA part!
		ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address &= 0xFFFFFFF; //Truncate the address to it's size!
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.LBA |= ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address; //Set the LBA part only!
	}
	else
	{
		ATA_LBA2CHS(channel,ATA_activeDrive(channel),ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address, &cylinder, &head, &sector); //Convert the current LBA address into a CHS value!
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh = ((cylinder >> 8) & 0xFF); //Cylinder high!
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow = (cylinder&0xFF); //Cylinder low!
		ATA_DRIVEHEAD_HEADW(channel,ATA_activeDrive(channel),head); //Head!
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectornumber = sector; //Sector number!
	}
}

OPTINLINE byte ATA_readsector(byte channel, byte command) //Read the current sector set up!
{
	uint_32 disk_size = ((ATA[channel].Drive[ATA_activeDrive(channel)].driveparams[61] << 16) | ATA[channel].Drive[ATA_activeDrive(channel)].driveparams[60]); //The size of the disk in sectors!
	if (ATA[channel].commandstatus == 1) //We're reading already?
	{
		if (!--ATA[channel].datasize) //Finished?
		{
			ATA_updatesector(channel); //Update the current sector!
			ATA[channel].commandstatus = 0; //We're back in command mode!
			EMU_setDiskBusy(ATA_Drives[channel][ATA_activeDrive(channel)], 0); //We're not reading anymore!
			return 1; //We're finished!
		}
	}
	if (ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address > disk_size) //Past the end of the disk?
	{
#ifdef ATA_LOG
		dolog("ATA", "Read Sector out of range:%i,%i=%08X/%08X!", channel, ATA_activeDrive(channel), ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address, disk_size);
#endif
		ATA_ERRORREGISTER_IDMARKNOTFOUNDW(channel,ATA_activeDrive(channel),1); //Not found!
		ATA_updatesector(channel); //Update the current sector!
		ATA[channel].commandstatus = 0xFF; //Error!
		EMU_setDiskBusy(ATA_Drives[channel][ATA_activeDrive(channel)], 0); //We're not reading anymore!
		return 0; //Stop!
	}

	if (readdata(ATA_Drives[channel][ATA_activeDrive(channel)], &ATA[channel].data, ((uint_64)ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address << 9), 0x200)) //Read the data from disk?
	{
		EMU_setDiskBusy(ATA_Drives[channel][ATA_activeDrive(channel)], 1); //We're reading!
		ATA_increasesector(channel); //Increase the current sector!

		ATA[channel].datablock = 0x200; //We're refreshing after this many bytes!
		ATA[channel].datapos = 0; //Initialise our data position!
		ATA[channel].commandstatus = 1; //Transferring data IN!
		ATA[channel].command = command; //Set the command to use when reading!
		return 1; //Process the block!
	}
	else //Error reading?
	{
		ATA_ERRORREGISTER_IDMARKNOTFOUNDW(channel,ATA_activeDrive(channel),1); //Not found!
		ATA_updatesector(channel); //Update the current sector!
		ATA[channel].commandstatus = 0xFF; //Error!
		EMU_setDiskBusy(ATA_Drives[channel][ATA_activeDrive(channel)], 0); //We're doing nothing!
		return 0; //Stop!
	}
	return 1; //We're finished!
}

OPTINLINE byte ATA_writesector(byte channel)
{
	uint_32 disk_size = ((ATA[channel].Drive[ATA_activeDrive(channel)].driveparams[61] << 16) | ATA[channel].Drive[ATA_activeDrive(channel)].driveparams[60]); //The size of the disk in sectors!
	if (ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address > disk_size) //Past the end of the disk?
	{
#ifdef ATA_LOG
		dolog("ATA", "Write Sector out of range:%i,%i=%08X/%08X!",channel,ATA_activeDrive(channel), ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address,disk_size);
#endif
		ATA_ERRORREGISTER_IDMARKNOTFOUNDW(channel,ATA_activeDrive(channel),1); //Not found!
		ATA_updatesector(channel); //Update the current sector!
		ATA[channel].commandstatus = 0xFF; //Error!
		EMU_setDiskBusy(ATA_Drives[channel][ATA_activeDrive(channel)], 0); //We're doing nothing!
		return 1; //We're finished!
	}

#ifdef ATA_LOG
	dolog("ATA", "Writing sector #%i!", ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address); //Log the sector we're writing to!
#endif
	EMU_setDiskBusy(ATA_Drives[channel][ATA_activeDrive(channel)], 2); //We're writing!
	if (writedata(ATA_Drives[channel][ATA_activeDrive(channel)], &ATA[channel].data, ((uint_64)ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address << 9), 0x200)) //Write the data to the disk?
	{
		ATA_increasesector(channel); //Increase the current sector!

		if (!--ATA[channel].datasize) //Finished?
		{
			ATA_updatesector(channel); //Update the current sector!
			ATA[channel].commandstatus = 0; //We're back in command mode!
#ifdef ATA_LOG
			dolog("ATA", "All sectors to be written written! Ready.");
#endif
			EMU_setDiskBusy(ATA_Drives[channel][ATA_activeDrive(channel)], 0); //We're doing nothing!
			return 1; //We're finished!
		}

#ifdef ATA_LOG
		dolog("ATA", "Process next sector...");
#endif
		//Process next sector!
		ATA[channel].datablock = 0x200; //We're refreshing after this many bytes!
		ATA[channel].datapos = 0; //Initialise our data position!
		ATA[channel].commandstatus = 2; //Transferring data OUT!
		return 1; //Process the block!
	}
	else //Write failed?
	{
#ifdef ATA_LOG
		dolog("ATA", "Write failed!"); //Log the sector we're writing to!
#endif
		if (drivereadonly(ATA_Drives[channel][ATA_activeDrive(channel)])) //R/O drive?
		{
#ifdef ATA_LOG
			dolog("ATA", "Because the drive is readonly!"); //Log the sector we're writing to!
#endif
			ATA_STATUSREGISTER_DRIVEWRITEFAULTW(channel,ATA_activeDrive(channel),1); //Write fault!
		}
		else
		{
#ifdef ATA_LOG
			dolog("ATA", "Because there was an error with the mounted disk image itself!"); //Log the sector we're writing to!
#endif
			ATA_ERRORREGISTER_UNCORRECTABLEDATAW(channel,ATA_activeDrive(channel),1); //Not found!
		}
		ATA_updatesector(channel); //Update the current sector!
		ATA[channel].commandstatus = 0xFF; //Error!
		EMU_setDiskBusy(ATA_Drives[channel][ATA_activeDrive(channel)], 0); //We're doing nothing!
	}
	return 0; //Finished!
}

OPTINLINE void ATAPI_giveresultsize(byte channel, word size)
{
	ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow = (size&0xFF); //Low byte of the result size!
	ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh = ((size>>8)&0xFF); //High byte of the result size!
}

OPTINLINE byte ATAPI_readsector(byte channel) //Read the current sector set up!
{
	byte *datadest = NULL; //Destination of our loaded data!
	uint_32 disk_size = ((ATA[channel].Drive[ATA_activeDrive(channel)].driveparams[61] << 16) | ATA[channel].Drive[ATA_activeDrive(channel)].driveparams[60]); //The size of the disk in sectors!
	if (ATA[channel].commandstatus == 1) //We're reading already?
	{
		if (!--ATA[channel].datasize) //Finished?
		{
			ATA[channel].commandstatus = 0; //We're back in command mode!
			EMU_setDiskBusy(ATA_Drives[channel][ATA_activeDrive(channel)], 0); //We're not reading anymore!
			ATAPI_giveresultsize(channel,0); //No result size!
			return 1; //We're finished!
		}
	}
	if (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_LBA > disk_size) //Past the end of the disk?
	{
#ifdef ATA_LOG
		dolog("ATA", "Read Sector out of range:%i,%i=%08X/%08X!", channel, ATA_activeDrive(channel), ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address, disk_size);
#endif
		ATA_ERRORREGISTER_IDMARKNOTFOUNDW(channel,ATA_activeDrive(channel),1); //Not found!
		ATA[channel].commandstatus = 0xFF; //Error!
		ATAPI_giveresultsize(channel,0); //No result size!
		EMU_setDiskBusy(ATA_Drives[channel][ATA_activeDrive(channel)], 0); //We're not reading anymore!
		return 0; //Stop!
	}

	if (ATA[channel].datablock==2352) //Raw CD-ROM data requested? Add the header, based on Bochs cdrom.cc!
	{
		memset(&ATA[channel].data, 0, 2352); //Clear any data we use!
		memset(&ATA[channel].data[1], 0xff, 10);
		uint_32 raw_block = ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_LBA + 150;
		ATA[channel].data[12] = (raw_block / 75) / 60;
		ATA[channel].data[13] = (raw_block / 75) % 60;
		ATA[channel].data[14] = (raw_block % 75);
		ATA[channel].data[15] = 0x01;
		datadest = &ATA[channel].data[0x10]; //Start of our read sector!
	}
	else
	{
		datadest = &ATA[channel].data[0]; //Start of our buffer!
	}

	if (readdata(ATA_Drives[channel][ATA_activeDrive(channel)], datadest, ((uint_64)ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_LBA << 9), 0x800)) //Read the data from disk?
	{
		EMU_setDiskBusy(ATA_Drives[channel][ATA_activeDrive(channel)], 1); //We're reading!
		ATA_increasesector(channel); //Increase the current sector!

		ATA[channel].datapos = 0; //Initialise our data position!
		ATA[channel].commandstatus = 1; //Transferring data IN!
		ATAPI_giveresultsize(channel,ATA[channel].datablock*ATA[channel].datasize); //Result size!
		return 1; //Process the block!
	}
	else //Error reading?
	{
		ATA_ERRORREGISTER_IDMARKNOTFOUNDW(channel,ATA_activeDrive(channel),1); //Not found!
		ATA[channel].commandstatus = 0xFF; //Error!
		ATAPI_giveresultsize(channel,0); //No result size!
		EMU_setDiskBusy(ATA_Drives[channel][ATA_activeDrive(channel)], 0); //We're doing nothing!
		return 0; //Stop!
	}
	return 1; //We're finished!
}

byte ATA_allowDiskChange(int disk) //Are we allowing this disk to be changed?
{
	byte disk_ATA, disk_channel, disk_nr;
	switch (disk) //What disk?
	{
		//Four disk numbers!
	case HDD0:
		disk_nr = 0;
		break;
	case HDD1:
		disk_nr = 1;
		break;
	case CDROM0:
		disk_nr = 2;
		break;
	case CDROM1:
		disk_nr = 3;
		break;
	default: //Unsupported?
		return 1; //Abort, we're unsupported, so allow changes!
	}
	disk_channel = ATA_DrivesReverse[disk_nr][0]; //The channel of the disk!
	disk_ATA = ATA_DrivesReverse[disk_nr][1]; //The master/slave of the disk!
	return !ATA[disk_channel].Drive[disk_ATA].preventMediumRemoval; //Are we not preventing removal of this medium?
}

byte ATAPI_supportedmodepagecodes[0x4] = { 0x01, 0x0D, 0x0E, 0x2A }; //Supported pages!
byte ATAPI_supportedmodepagecodes_length[0x4] = {0x6,0x6,0xD,0xC}; //The length of the pages stored in our memory!

OPTINLINE byte ATA_dataIN(byte channel) //Byte read from data!
{
	byte result;
	switch (ATA[channel].command) //What command?
	{
	case 0x20:
	case 0x21: //Read sectors?
	case 0x22: //Read long (w/retry)?
	case 0x23: //Read long (w/o retry)?
		result = ATA[channel].data[ATA[channel].datapos++]; //Read the data byte!
		if (ATA[channel].datapos == ATA[channel].datablock) //Full block read?
		{
			if (ATA_readsector(channel,ATA[channel].command)) //Next sector read?
			{
				ATA_IRQ(channel, ATA_activeDrive(channel)); //Give our requesting IRQ!
			}
		}
        return result; //Give the result!
		break;
	case 0xA0: //PACKET?
		if (!ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_processingPACKET) //Sending data?
		{
			switch (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[0]) //What command?
			{
			case 0x25: //Read capacity?
			case 0x12: //Inquiry?
			case 0x03: //REQUEST SENSE(Mandatory)?
			case 0x5A: //MODE SENSE(10)(Mandatory)?
			case 0x42: //Read sub-channel (mandatory)?
			case 0x43: //Read TOC (mandatory)?
			case 0x44: //Read header (mandatory)?
				result = ATA[channel].data[ATA[channel].datapos++]; //Read the data byte!
				if (ATA[channel].datapos == ATA[channel].datablock) //Full block read?
				{
					ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
				}
				return result; //Give the result!
				break;
			case 0x28: //Read sectors (10) command(Mandatory)?
			case 0xA8: //Read sector (12) command(Mandatory)?
			case 0xBE: //Read CD command(mandatory)?
			case 0xB9: //Read CD MSF (mandatory)?
				result = ATA[channel].data[ATA[channel].datapos++]; //Read the data byte!
				if (ATA[channel].datapos==ATA[channel].datablock) //Full block read?
				{
					if (ATAPI_readsector(channel)) //Next sector read?
					{
						ATA_IRQ(channel,ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
					}
				}
				return result; //Give the result!
				break;
			default: //Unknown command?
				break;
			}
		}
		break;
	case 0xEC: //Identify?
	case 0xA1: //IDENTIFY PACKET DEVICE?
		result = ATA[channel].data[ATA[channel].datapos++]; //Read the result byte!
		if (ATA[channel].datapos == ATA[channel].datablock) //Fully read?
		{
			ATA[channel].commandstatus = 0; //Reset command!
			ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
		}
		return result; //Give the result byte!
	default: //Unknown?
		break;
	}
	return 0; //Unknown data!
}

void ATAPI_executeData(byte channel); //Prototype for ATAPI data processing!

void ATAPI_PendingExecuteCommand(byte channel) //We're pending until execution!
{
	ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PendingExecuteCommand = 20000.0; //Initialize timing to 20us!
	ATA[channel].commandstatus = 3; //We're pending until ready!
}

OPTINLINE void ATA_dataOUT(byte channel, byte data) //Byte written to data!
{
	switch (ATA[channel].command) //What command?
	{
	case 0x30: //Write sector(s) (w/retry)?
	case 0x31: //Write sectors (w/o retry)?
	case 0x32: //Write long (w/retry)?
	case 0x33: //Write long (w/o retry)?
		ATA[channel].data[ATA[channel].datapos++] = data; //Write the data byte!
		if (ATA[channel].datapos == ATA[channel].datablock) //Full block read?
		{
			if (ATA_writesector(channel)) //Sector written and to write another sector?
			{
				ATA_IRQ(channel, ATA_activeDrive(channel)); //Give our requesting IRQ!
			}
		}
		break;
	case 0xA0: //ATAPI: PACKET!
		if (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_processingPACKET) //Are we processing a packet?
		{
			ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[ATA[channel].datapos++] = data; //Add the packet byte!
			if (ATA[channel].datapos==12) //Full packet written?
			{
				ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_processingPACKET = 0; //We're not processing a packet anymore, from now on we're data only!
				ATAPI_PendingExecuteCommand(channel); //Execute the ATAPI command!
			}
		}
		else //We're processing data for an ATAPI packet?
		{
			ATA[channel].data[ATA[channel].datapos++] = data; //Write the data byte!
			if (ATA[channel].datapos == ATA[channel].datablock) //Full block read?
			{
				ATAPI_executeData(channel); //Execute the data process!
			}
		}
		break;
	default: //Unknown?
		break;
	}
}

void ATAPI_executeData(byte channel) //Prototype for ATAPI data processing!
{
	word pageaddr;
	byte pagelength; //The length of the page!
	switch (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[0]) //What command?
	{
	case 0x55: //MODE SELECT(10)(Mandatory)?
		//Store the data, just ignore it!
		//Copy pages that are supported to their location in the Active Mode data!
		for (pageaddr=0;pageaddr<ATA[channel].datablock;) //Process all available data!
		{
			pagelength = ATA[channel].data[pageaddr + 1]-1; //This value is the last byte used minus 1(zero-based)!
			switch (ATA[channel].data[pageaddr]&0x3F) //What page code?
			{
				case 0x01: //Read error recovery page (Mandatory)?
					pagelength = MAX(pagelength, 0x6); //Maximum length to apply!
					memcpy(&ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_ModeData[0x01 << 8], &ATA[channel].data[pageaddr + 2], pagelength); //Copy the page data to our position, simply copy all data!
					break;
				case 0x0D: //CD-ROM page?
					pagelength = MAX(pagelength, 0x6); //Maximum length to apply!
					memcpy(&ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_ModeData[0x0D << 8], &ATA[channel].data[pageaddr + 2], pagelength); //Copy the page data to our position, simply copy all data!
					break;
				case 0x0E: //CD-ROM audio control page?
					pagelength = MAX(pagelength,0xD); //Maximum length to apply!
					memcpy(&ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_ModeData[0x0E<<8],&ATA[channel].data[pageaddr+2],pagelength); //Copy the page data to our position, simply copy all data!
					break;
				case 0x2A: //CD-ROM capabilities & Mechanical Status Page?
					pagelength = MAX(pagelength, 0xC); //Maximum length to apply!
					memcpy(&ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_ModeData[0x2A << 8], &ATA[channel].data[pageaddr + 2], pagelength); //Copy the page data to our position, simply copy all data!
					break;
				default: //Unknown page? Ignore it!
					break;
			}
			pageaddr += ATA[channel].data[pageaddr+1]+1; //Jump to the next block, if any!
		}
		ATA[channel].commandstatus = 0; //Reset status: we're done!
		ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're done!
		break;
	case 0x28: //Read sectors (10) command(Mandatory)?
	case 0xA8: //Read sectors command!
		ATA[channel].commandstatus = 0; //Reset status: we're done!
		ATA_IRQ(channel,ATA_activeDrive(channel)); //Raise an IRQ: we're done!
		break;
	}	
}

//read_TOC conversion from http://bochs.sourceforge.net/cgi-bin/lxr/source/iodev/hdimage/cdrom.cc
byte Bochs_generateTOC(byte* buf, sword* length, byte msf, sword start_track, sword format, byte channel, byte drive)
{
	unsigned i;
	uint_32 blocks;
	int len = 4;
	switch (format) {
		case 0:
				// From atapi specs : start track can be 0-63, AA
				if ((start_track > 1) && (start_track != 0xaa))
					return 0;
				buf[2] = 1;
				buf[3] = 1;
				if (start_track <= 1) {
					buf[len++] = 0; // Reserved
					buf[len++] = 0x14; // ADR, control
					buf[len++] = 1; // Track number
					buf[len++] = 0; // Reserved
					// Start address
					if (msf) {
						buf[len++] = 0; // reserved
						buf[len++] = 0; // minute
						buf[len++] = 2; // second
						buf[len++] = 0; // frame
					}
					else {
						buf[len++] = 0;
						buf[len++] = 0;
						buf[len++] = 0;
						buf[len++] = 0; // logical sector 0
					}
				}
				// Lead out track
				buf[len++] = 0; // Reserved
				buf[len++] = 0x16; // ADR, control
				buf[len++] = 0xaa; // Track number
				buf[len++] = 0; // Reserved
				blocks = ((ATA[channel].Drive[drive].driveparams[61] << 16) | ATA[channel].Drive[drive].driveparams[60]); //Get the drive size from the disk information, in 2KB blocks!
				// Start address
				if (msf) {
					buf[len++] = 0; // reserved
					buf[len++] = (byte)(((blocks + 150) / 75) / 60); // minute
					buf[len++] = (byte)(((blocks + 150) / 75) % 60); // second
					buf[len++] = (byte)((blocks + 150) % 75); // frame;
				}
				else {
					buf[len++] = (blocks >> 24) & 0xff;
					buf[len++] = (blocks >> 16) & 0xff;
					buf[len++] = (blocks >> 8) & 0xff;
					buf[len++] = (blocks >> 0) & 0xff;
				}
				buf[0] = ((len - 2) >> 8) & 0xff;
				buf[1] = (len - 2) & 0xff;
				break;
			case 1:
				// multi session stuff - emulate a single session only
				buf[0] = 0;
				buf[1] = 0x0a;
				buf[2] = 1;
				buf[3] = 1;
				for (i = 0; i < 8; i++)
					buf[4 + i] = 0;
				len = 12;
				break;
			case 2:
				// raw toc - emulate a single session only (ported from qemu)
				buf[2] = 1;
				buf[3] = 1;
				for (i = 0; i < 4; i++) {
					buf[len++] = 1;
					buf[len++] = 0x14;
					buf[len++] = 0;
					if (i < 3) {
						buf[len++] = 0xa0 + i;
					}
					else {
						buf[len++] = 1;
					}
					buf[len++] = 0;
					buf[len++] = 0;
					buf[len++] = 0;
					if (i < 2) {
						buf[len++] = 0;
						buf[len++] = 1;
						buf[len++] = 0;
						buf[len++] = 0;
					}
					else if (i == 2) {
						blocks = ((ATA[channel].Drive[drive].driveparams[61] << 16) | ATA[channel].Drive[drive].driveparams[60]); //Capacity, in 2KB sectors!
						if (msf) {
							buf[len++] = 0; // reserved
							buf[len++] = (byte)(((blocks + 150) / 75) / 60); // minute
							buf[len++] = (byte)(((blocks + 150) / 75) % 60); // second
							buf[len++] = (byte)((blocks + 150) % 75); // frame;
						}
						else {
							buf[len++] = (blocks >> 24) & 0xff;
							buf[len++] = (blocks >> 16) & 0xff;
							buf[len++] = (blocks >> 8) & 0xff;
							buf[len++] = (blocks >> 0) & 0xff;
						}
					}
					else {
						buf[len++] = 0;
						buf[len++] = 0;
						buf[len++] = 0;
						buf[len++] = 0;
					}
				}
				buf[0] = ((len - 2) >> 8) & 0xff;
				buf[1] = (len - 2) & 0xff;
			break;
		default:
			return 0;
	}
	*length = len;
	return 1;
}

byte encodeBCD8ATA(byte value)
{
	INLINEREGISTER byte temp, result = 0;
	temp = value; //Load the original value!
	temp %= 100; //Rest to be sure!
	result |= (0x0010 * (temp / 10)); //Factor 10!
	temp %= 10;
	result |= temp; //Factor 1!
	return result;
}

byte decodeBCD8ATA(byte bcd)
{
	INLINEREGISTER byte temp, result = 0;
	temp = bcd; //Load the BCD value!
	result += (temp & 0xF); //Factor 1!
	temp >>= 4;
	result += (temp & 0xF) * 10; //Factor 10!
	return result; //Give the decoded integer value!
}

uint_32 MSF2LBA(byte M, byte S, byte F)
{
	return (((decodeBCD8ATA(M)*60)+decodeBCD8ATA(S))*75)+decodeBCD8ATA(F); //75 frames per second, 60 seconds in a minute!
}

void LBA2MSF(uint_32 LBA, byte *M, byte *S, byte *F)
{
	uint_32 rest;
	rest = LBA; //Load LBA!
	*M = rest/(60*75); //Minute!
	rest -= *M*(60*75); //Rest!
	*S = rest/75; //Second!
	rest -= *S*75;
	*F = rest%75; //Frame, if any!
	*M = encodeBCD8ATA(*M);
	*S = encodeBCD8ATA(*S);
	*F = encodeBCD8ATA(*F);
}

//List of mandatory commands from http://www.bswd.com/sff8020i.pdf page 106 (ATA packet interface for CD-ROMs SFF-8020i Revision 2.6)
void ATAPI_executeCommand(byte channel, byte drive) //Prototype for ATAPI execute Command!
{
	//We're to move to either HPD3(raising an IRQ when enabled, which moves us to HPD2) or HPD2(data phase). Busy must be cleared to continue transferring, otherwise software's waiting. Next we start HPD4(data transfer phase) to transfer data if needed, finish otherwise.
	//Stuff based on Bochs
	byte MSF; //MSF bit!
	byte sub_Q; //SubQ bit!
	byte data_format; //Sub-channel Data Format
	//byte track_number; //Track number
	word alloc_length; //Allocation length!
	word ret_len; //Returned length of possible data!
	byte starting_track;
	byte format;
	sword toc_length = 0;
	byte transfer_req;
	uint_32 endLBA; //When does the LBA addressing end!

	//Our own stuff!
	byte aborted = 0;
	byte abortreason = 5; //Error cause is no disk inserted? Default to 5&additional sense code 0x20 for invalid command.
	byte additionalsensecode = 0x20; //Invalid command operation code.
	byte isvalidpage = 0; //Valid page?
	uint_32 packet_datapos;
	byte i;
	uint_32 disk_size,LBA;
	disk_size = (ATA[channel].Drive[drive].driveparams[61]<<16) | ATA[channel].Drive[drive].driveparams[60]; //Disk size in 512 byte sectors!
	disk_size >>= 2; //We're 4096 byte sectors instead of 512 byte sectors!
	switch (ATA[channel].Drive[drive].ATAPI_PACKET[0]) //What command?
	{
	case 0x00: //TEST UNIT READY(Mandatory)?
		if (!is_mounted(ATA_Drives[channel][drive])) { abortreason = 2;additionalsensecode = 0x3A;goto ATAPI_invalidcommand; } //Error out if not present!
		//Valid disk loaded?
		ATA[channel].Drive[drive].ERRORREGISTER = 0; //Clear error register!
		ATAPI_SENSEPACKET_SENSEKEYW(channel,drive,0x00); //Reason of the error
		ATAPI_SENSEPACKET_ADDITIONALSENSECODEW(channel,drive,0x00); //Extended reason code
		ATAPI_SENSEPACKET_ERRORCODEW(channel,drive,0x70); //Default error code?
		ATAPI_SENSEPACKET_ADDITIONALSENSELENGTHW(channel,drive,8); //Additional Sense Length = 8?
		ATAPI_SENSEPACKET_INFORMATION0W(channel,drive,0); //No info!
		ATAPI_SENSEPACKET_INFORMATION1W(channel,drive,0); //No info!
		ATAPI_SENSEPACKET_INFORMATION2W(channel,drive,0); //No info!
		ATAPI_SENSEPACKET_INFORMATION3W(channel,drive,0); //No info!
		ATAPI_SENSEPACKET_COMMANDSPECIFICINFORMATION0W(channel,drive,0); //No command specific information?
		ATAPI_SENSEPACKET_COMMANDSPECIFICINFORMATION1W(channel,drive,0); //No command specific information?
		ATAPI_SENSEPACKET_COMMANDSPECIFICINFORMATION2W(channel,drive,0); //No command specific information?
		ATAPI_SENSEPACKET_COMMANDSPECIFICINFORMATION3W(channel,drive,0); //No command specific information?
		ATAPI_SENSEPACKET_VALIDW(channel,drive,1); //We're valid!
		ATAPI_giveresultsize(channel,0); //No result size!
		break;
	case 0x03: //REQUEST SENSE(Mandatory)?
		if (!is_mounted(ATA_Drives[channel][drive])) { abortreason = 2;additionalsensecode = 0x3A;goto ATAPI_invalidcommand; } //Error out if not present!
		//Byte 4 = allocation length
		ATA[channel].datapos = 0; //Start of data!
		ATA[channel].datablock = MIN(ATA[channel].Drive[drive].ATAPI_PACKET[4],sizeof(ATA[channel].Drive[drive].SensePacket)); //Size of a block to transfer!
		ATA[channel].datasize = 1; //How many blocks to transfer!

		//Now fill the packet with data!
		memcpy(&ATA[channel].data, &ATA[channel].Drive[drive].SensePacket, ATA[channel].datablock); //Give the result!
		//Leave the rest of the information cleared (unknown/unspecified)
		ATA[channel].commandstatus = 1; //Transferring data IN!
		ATAPI_giveresultsize(channel,ATA[channel].datablock*ATA[channel].datasize); //Result size!
		ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
		break;
	case 0x12: //INQUIRY(Mandatory)?
		//We do succeed without media?
		//if (!is_mounted(ATA_Drives[channel][drive])) {abortreason=2;additionalsensecode=0x3A;goto ATAPI_invalidcommand;} //Error out if not present!
		//Byte 4 = allocation length
		ATA[channel].datapos = 0; //Start of data!
		ATA[channel].datablock = ATA[channel].Drive[drive].ATAPI_PACKET[4]; //Size of a block to transfer!
		ATA[channel].datasize = 1; //How many blocks to transfer!
		memset(ATA[channel].data,0,ATA[channel].datablock); //Clear the result!
		//Now fill the packet with data!
		ATA[channel].data[0] = 0x05; //We're a CD-ROM drive!
		ATA[channel].data[1] = 0x80; //We're always removable!
		ATA[channel].data[3] = (4<<4); //We're ATAPI version 4, response data format 0?
		//Leave the rest of the information cleared (unknown/unspecified)
		ATA[channel].commandstatus = 1; //Transferring data IN!
		ATAPI_giveresultsize(channel,ATA[channel].datablock*ATA[channel].datasize); //Result size!
		ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
		break;
	case 0x55: //MODE SELECT(10)(Mandatory)?
		if (!is_mounted(ATA_Drives[channel][drive])){abortreason=2;additionalsensecode=0x3A;goto ATAPI_invalidcommand;} //Error out if not present!
		//Byte 4 = allocation length
		ATA[channel].datapos = 0; //Start of data!
		ATA[channel].datablock = (ATA[channel].Drive[drive].ATAPI_PACKET[7]<<1)|ATA[channel].Drive[drive].ATAPI_PACKET[8]; //Size of a block to transfer!
		ATA[channel].datasize = 1; //How many blocks to transfer!
		memset(ATA[channel].data, 0, ATA[channel].datablock); //Clear the result!
		//Leave the rest of the information cleared (unknown/unspecified)
		ATA[channel].commandstatus = 2; //Transferring data OUT!
		ATAPI_giveresultsize(channel,ATA[channel].datablock*ATA[channel].datasize); //Result size!
		ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
		break;
	case 0x5A: //MODE SENSE(10)(Mandatory)?
		if (!is_mounted(ATA_Drives[channel][drive])){abortreason=2;additionalsensecode=0x3A;goto ATAPI_invalidcommand;} //Error out if not present!
		ATA[channel].datapos = 0; //Start of data!
		ATA[channel].datablock = (ATA[channel].Drive[drive].ATAPI_PACKET[7] << 1) | ATA[channel].Drive[drive].ATAPI_PACKET[8]; //Size of a block to transfer!
		ATA[channel].datasize = 1; //How many blocks to transfer!
		ATAPI_giveresultsize(channel,ATA[channel].datablock*ATA[channel].datasize); //Result size!
		memset(ATA[channel].data, 0, ATA[channel].datablock); //Clear the result!
		//Leave the rest of the information cleared (unknown/unspecified)
		ATA[channel].commandstatus = 1; //Transferring data IN for the result!

		for (i=0;i<NUMITEMS(ATAPI_supportedmodepagecodes);i++) //Check all supported codes!
		{
			if (ATAPI_supportedmodepagecodes[i] == (ATA[channel].Drive[drive].ATAPI_PACKET[2]&0x3F)) //Page found in our page storage?
			{
				//Valid?
				if (ATAPI_supportedmodepagecodes_length[i]<=ATA[channel].datablock) //Valid page size?
				{
					//Generate a header for the packet!
					ATA[channel].data[0] = ATAPI_supportedmodepagecodes[i]; //The page code and PS bit!
					ATA[channel].data[1] = ATAPI_supportedmodepagecodes_length[i]; //Actual page length that's stored(which follows right after, either fully or partially)!
					switch (ATA[channel].Drive[drive].ATAPI_PACKET[2]>>6) //What kind of packet are we requesting?
					{
					case CDROM_PAGECONTROL_CHANGEABLE: //1 bits for all changable values?
						for (packet_datapos=0;packet_datapos<(ATA[channel].datablock-2);++packet_datapos) //Process all our bits that are changable!
						{
							ATA[channel].data[packet_datapos+2] = ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_SupportedMask[(ATAPI_supportedmodepagecodes[i]<<8)|packet_datapos]; //Give the raw mask we're using!
						}
						break;
					case CDROM_PAGECONTROL_CURRENT: //Current values?
						for (packet_datapos = 0;packet_datapos<(ATA[channel].datablock-2);++packet_datapos) //Process all our bits that are changable!
						{
							ATA[channel].data[packet_datapos+2] = ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_ModeData[(ATAPI_supportedmodepagecodes[i] << 8) | packet_datapos]&ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_SupportedMask[(ATAPI_supportedmodepagecodes[i] << 8) | packet_datapos]; //Give the raw mask we're using!
						}
						break;
					case CDROM_PAGECONTROL_DEFAULT: //Default values?
						for (packet_datapos = 0;packet_datapos<(ATA[channel].datablock-2);++packet_datapos) //Process all our bits that are changable!
						{
							ATA[channel].data[packet_datapos+2] = ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_DefaultModeData[(ATAPI_supportedmodepagecodes[i] << 8) | packet_datapos] & ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_SupportedMask[(ATAPI_supportedmodepagecodes[i] << 8) | packet_datapos]; //Give the raw mask we're using!
						}
						break;
					case CDROM_PAGECONTROL_SAVED: //Currently saved values?
						goto ATAPI_invalidcommand; //Saved data isn't supported!
						break;
					}
					isvalidpage = 1; //Were valid!
					ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
				}
				else
				{
					goto ATAPI_invalidcommand; //Error out!
				}
				break; //Stop searching!
			}
			if (isvalidpage==0) //Invalid page?
			{
				goto ATAPI_invalidcommand; //Error out!
			}
		}
		break;
	case 0x1E: //Prevent/Allow Medium Removal(Mandatory)?
		if (!is_mounted(ATA_Drives[channel][drive])){abortreason=2;additionalsensecode=0x3A;goto ATAPI_invalidcommand;} //Error out if not present!
		ATA[channel].Drive[ATA_activeDrive(channel)].preventMediumRemoval = (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[4]&1); //Are we preventing the storage medium to be removed?
		ATAPI_giveresultsize(channel,0); //No result size!
		ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
		ATA[channel].commandstatus = 0; //New command can be specified!
		break;
	case 0xBE: //Read CD command(mandatory)?
		if (!is_mounted(ATA_Drives[channel][drive])) { abortreason = 2;additionalsensecode = 0x3A;goto ATAPI_invalidcommand; } //Error out if not present!
		LBA = (((((ATA[channel].Drive[drive].ATAPI_PACKET[2] << 8) | ATA[channel].Drive[drive].ATAPI_PACKET[3]) << 8) | ATA[channel].Drive[drive].ATAPI_PACKET[4]) << 8) | ATA[channel].Drive[drive].ATAPI_PACKET[5]; //The LBA address!
		ATA[channel].datasize = ATA[channel].Drive[drive].ATAPI_PACKET[8]|ATA[channel].Drive[drive].ATAPI_PACKET[7]|ATA[channel].Drive[drive].ATAPI_PACKET[6]; //The amount of sectors to transfer!
		transfer_req = ATA[channel].Drive[drive].ATAPI_PACKET[9]; //Requested type of packets!
		if (!ATA[channel].datasize) //Nothing to transfer?
		{
			//Execute NOP command!
			readCDNOP: //NOP for reading CD directly!
			ATAPI_giveresultsize(channel,0); //Result size!
			ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
			ATA[channel].commandstatus = 0; //New command can be specified!
		}
		else //Normal processing!
		{
			ATA[channel].datablock = 0x800; //Default block size!

			if ((LBA>disk_size) || ((LBA + ATA[channel].datasize - 1)>disk_size)) { abortreason = 5;additionalsensecode = 0x21;goto ATAPI_invalidcommand; } //Error out when invalid sector!

			switch (transfer_req&0xF8) //What type to transfer?
			{
			case 0x00: goto readCDNOP; //Same as NOP!
			case 0xF8: ATA[channel].datablock = 2352; //We're using CD direct packets! Different kind of format wrapper!
			case 0x10: //Normal 2KB sectors?
				ATA[channel].datapos = 0; //Start of data!
				ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_LBA = LBA; //The LBA to use!
				if (ATAPI_readsector(channel)) //Sector read?
				{
					ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
				}
				break;
			default: //Unknown request?
				abortreason = 5; //Error category!
				additionalsensecode = 0x24; //Invalid Field in command packet!
				ATAPI_giveresultsize(channel,0); //Result size!
				goto ATAPI_invalidcommand;
			}
		}
		break;
	case 0xB9: //Read CD MSF (mandatory)?
		if (!is_mounted(ATA_Drives[channel][drive])) { abortreason = 2;additionalsensecode = 0x3A;goto ATAPI_invalidcommand; } //Error out if not present!
		LBA = MSF2LBA(ATA[channel].Drive[drive].ATAPI_PACKET[3], ATA[channel].Drive[drive].ATAPI_PACKET[4], ATA[channel].Drive[drive].ATAPI_PACKET[5]); //The LBA address!
		endLBA = MSF2LBA(ATA[channel].Drive[drive].ATAPI_PACKET[6], ATA[channel].Drive[drive].ATAPI_PACKET[7], ATA[channel].Drive[drive].ATAPI_PACKET[8]); //The LBA address!

		if (LBA>endLBA) //LBA shall not be past the end!
		{
			abortreason = 5; //Error category!
			additionalsensecode = 0x24; //Invalid Field in command packet!
			goto ATAPI_invalidcommand;
		}

		ATA[channel].datasize = (endLBA-LBA); //The amount of sectors to transfer! 0 is valid!
		transfer_req = ATA[channel].Drive[drive].ATAPI_PACKET[9]; //Requested type of packets!
		if (!ATA[channel].datasize) //Nothing to transfer?
		{
			//Execute NOP command!
			readCDMSFNOP: //NOP for reading CD directly!
			ATAPI_giveresultsize(channel,0); //No result size!
			ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
			ATA[channel].commandstatus = 0; //New command can be specified!
		}
		else //Normal processing!
		{
			ATA[channel].datablock = 0x800; //Default block size!

			if ((LBA>disk_size) || ((LBA + ATA[channel].datasize - 1)>disk_size)) { abortreason = 5;additionalsensecode = 0x21;goto ATAPI_invalidcommand; } //Error out when invalid sector!

			switch (transfer_req&0xF8) //What type to transfer?
			{
			case 0x00: goto readCDMSFNOP; //Same as NOP!
			case 0xF8: ATA[channel].datablock = 2352; //We're using CD direct packets! Different kind of format wrapper!
			case 0x10: //Normal 2KB sectors?
				ATA[channel].datapos = 0; //Start of data!
				ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_LBA = LBA; //The LBA to use!
				if (ATAPI_readsector(channel)) //Sector read?
				{
					ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
				}
				break;
			default: //Unknown request?
				abortreason = 5; //Error category!
				additionalsensecode = 0x24; //Invalid Field in command packet!
				goto ATAPI_invalidcommand;
			}
		}
		break;
	case 0x44: //Read header (mandatory)?
		if (!is_mounted(ATA_Drives[channel][drive])) { abortreason = 2;additionalsensecode = 0x3A;goto ATAPI_invalidcommand; } //Error out if not present!
		if (!ATA[channel].Drive[ATA_activeDrive(channel)].isSpinning) { abortreason = 2;additionalsensecode = 0x4;goto ATAPI_invalidcommand; } //We need to be running!

		LBA = (((((ATA[channel].Drive[drive].ATAPI_PACKET[2] << 8) | ATA[channel].Drive[drive].ATAPI_PACKET[3]) << 8) | ATA[channel].Drive[drive].ATAPI_PACKET[4]) << 8) | ATA[channel].Drive[drive].ATAPI_PACKET[5]; //The LBA address!
		alloc_length = (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[7] << 1) | (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[8]); //Allocated length!
		//[9]=Amount of sectors, [2-5]=LBA address, LBA mid/high=2048.

		if (LBA>disk_size) { abortreason = 5;additionalsensecode = 0x21;goto ATAPI_invalidcommand; } //Error out when invalid sector!

		//Now, build the packet!

		ret_len = 8; //Always try to return 8 bytes of data!

		memset(&ATA[channel].data,0,8); //Clear all possible data!
		if (ATA[channel].Drive[drive].ATAPI_PACKET[1]&2) //MSF packet requested?
		{
			ATA[channel].data[0] = 1; //User data here! 2048 bytes, mode 1 sector!
			LBA2MSF(LBA,&ATA[channel].data[5],&ATA[channel].data[6],&ATA[channel].data[7]); //Try and get the MSF address based on the LBA!
		}
		else //LBA packet requested?
		{
			ATA[channel].data[0] = 1; //User data here! 2048 bytes, mode 1 sector!
			ATA[channel].data[4] = (LBA>>24)&0xFF;
			ATA[channel].data[5] = (LBA>>16)&0xFF;
			ATA[channel].data[6] = (LBA>>8)&0xFF;
			ATA[channel].data[7] = (LBA&0xFF);
		}

		//Process the command normally!
		//Leave the rest of the information cleared (unknown/unspecified)
		ATA[channel].datasize = 1; //One block to transfer!
		ATA[channel].datablock = MIN(alloc_length, ret_len); //Give the smallest result, limit by allocation length!
		ATA[channel].commandstatus = 1; //Transferring data IN for the result!
		ATAPI_giveresultsize(channel,ATA[channel].datablock*ATA[channel].datasize); //Result size!
		break;
	case 0x42: //Read sub-channel (mandatory)?
		MSF = (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[1]&2); //MSF bit!
		sub_Q = (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[2] & 0x40); //SubQ bit!
		data_format = ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[3]; //Sub-channel Data Format
		//track_number = ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[6]; //Track number
		alloc_length = (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[7]<<1)|ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[8]; //Allocation length!
		ret_len = 4;
		if (!is_mounted(ATA_Drives[channel][drive])) { abortreason = 2;additionalsensecode = 0x3A;goto ATAPI_invalidcommand; } //Error out if not present!
		memset(ATA[channel].data,0,24); //Clear any and all data we might be using!
		ATA[channel].data[0] = 0;
		ATA[channel].data[1] = 0; //audio not supported
		ATA[channel].data[2] = 0;
		ATA[channel].data[3] = 0;
		if (sub_Q) //!sub_q==header only
		{
			if ((data_format==2) || (data_format==3)) //UPC or ISRC
			{
				ret_len = 24;
				ATA[channel].data[4] = data_format;
				if (data_format==3)
				{
					ATA[channel].data[5] = 0x14;
					ATA[channel].data[6] = 1;
				}
				ATA[channel].data[8] = 0;
			}
			else
			{
				abortreason = 5; //Error category!
				additionalsensecode = 0x24; //Invalid Field in command packet!
				goto ATAPI_invalidcommand;
			}
		}

		//Process the command normally!
		//Leave the rest of the information cleared (unknown/unspecified)
		ATA[channel].datasize = 1; //One block to transfer!
		ATA[channel].datablock = MIN(alloc_length,ret_len); //Give the smallest result, limit by allocation length!
		ATA[channel].commandstatus = 1; //Transferring data IN for the result!
		ATAPI_giveresultsize(channel,ATA[channel].datablock*ATA[channel].datasize); //Result size!
		break;
	case 0x43: //Read TOC (mandatory)?
		if (!is_mounted(ATA_Drives[channel][drive])) { abortreason = 2;additionalsensecode = 0x3A;goto ATAPI_invalidcommand; } //Error out if not present!
		MSF = (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[1]>>1)&1;
		starting_track = ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[6]; //Starting track!
		alloc_length = (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[7]<<1)|(ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[8]); //Allocated length!
		format = (ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_PACKET[9]>>6); //The format of the packet!
		switch (format)
		{
		case 0:
		case 1:
		case 2:
			if (!Bochs_generateTOC(&ATA[channel].data[0],&toc_length,MSF,starting_track,format,channel,ATA_activeDrive(channel)))
			{
				goto invalidTOCrequest; //Invalid TOC request!
			}
			ATA[channel].datablock = MIN(toc_length,alloc_length); //Take the lesser length!
			ATA[channel].datasize = 1; //One block to transfer!
			ATA[channel].commandstatus = 1; //Transferring data IN for the result!
			ATAPI_giveresultsize(channel,ATA[channel].datablock*ATA[channel].datasize); //Result size!
			ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
			break;
		default:
			invalidTOCrequest:
			abortreason = 5; //Error category!
			additionalsensecode = 0x24; //Invalid Field in command packet!
			goto ATAPI_invalidcommand;
		}
		break;
	case 0x2B: //Seek (Mandatory)?
		if (!is_mounted(ATA_Drives[channel][drive])) { abortreason = 2;additionalsensecode = 0x3A;goto ATAPI_invalidcommand; } //Error out if not present!
		if (!ATA[channel].Drive[ATA_activeDrive(channel)].isSpinning) { abortreason = 2;additionalsensecode = 0x4;goto ATAPI_invalidcommand; } //We need to be running!
		//[9]=Amount of sectors, [2-5]=LBA address, LBA mid/high=2048.
		LBA = (((((ATA[channel].Drive[drive].ATAPI_PACKET[2] << 8) | ATA[channel].Drive[drive].ATAPI_PACKET[3]) << 8) | ATA[channel].Drive[drive].ATAPI_PACKET[4]) << 8) | ATA[channel].Drive[drive].ATAPI_PACKET[5]; //The LBA address!

		if (LBA>disk_size) { abortreason = 5;additionalsensecode = 0x21;goto ATAPI_invalidcommand; } //Error out when invalid sector!

		//Save the Seeked LBA somewhere? Currently unused?

		ATAPI_giveresultsize(channel,0); //No result size!
		ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
		ATA[channel].commandstatus = 0; //New command can be specified!
		break;
	case 0x4E: //Stop play/scan (Mandatory)?
		//Simply ignore the command for now, as audio is unsupported?
		if (!is_mounted(ATA_Drives[channel][drive])) { abortreason = 2;additionalsensecode = 0x3A;goto ATAPI_invalidcommand; } //Error out if not present!
		if (!ATA[channel].Drive[ATA_activeDrive(channel)].isSpinning) { abortreason = 2;additionalsensecode = 0x4;goto ATAPI_invalidcommand; } //We need to be running!
		ATAPI_giveresultsize(channel,0); //No result size!
		ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
		ATA[channel].commandstatus = 0; //New command can be specified!
		break;
	case 0x1B: //Start/stop unit(Mandatory)?
		switch (ATA[channel].Drive[drive].ATAPI_PACKET[4] & 3) //What kind of action to take?
		{
		case 0: //Stop the disc?
			ATA[channel].Drive[ATA_activeDrive(channel)].isSpinning = 0; //We're stopped now!
			break;
		case 1: //Start the disc and read the TOC?
			ATA[channel].Drive[ATA_activeDrive(channel)].isSpinning = 1; //We're running now!
			break;
		case 2: //Eject the disc if possible?
			if (ATA_allowDiskChange(ATA_Drives[channel][ATA_activeDrive(channel)]) && (!ATA[channel].Drive[ATA_activeDrive(channel)].isSpinning)) //Do we allow the disc to be changed? Don't allow ejecting when running!
			{
				requestEjectDisk(ATA_Drives[channel][ATA_activeDrive(channel)]); //Request for the specified disk to be ejected!
			}
			else //Not allowed to change?
			{
				abortreason = 2; //Not ready!
				additionalsensecode = 0x53; //Media removal prevented!
				goto ATAPI_invalidcommand; //Not ready, media removal prevented!
			}
			break;
		case 3: //Load the disc (Close tray)?
			break;
		}
		ATAPI_giveresultsize(channel,0); //No result size!
		ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
		ATA[channel].commandstatus = 0; //New command can be specified!
		break;
	case 0x28: //Read sectors (10) command(Mandatory)?
	case 0xA8: //Read sectors (12) command(Mandatory)!
		if (!is_mounted(ATA_Drives[channel][drive])){abortreason=2;additionalsensecode=0x3A;goto ATAPI_invalidcommand;} //Error out if not present!
		if (!ATA[channel].Drive[ATA_activeDrive(channel)].isSpinning) { abortreason = 2;additionalsensecode = 0x4;goto ATAPI_invalidcommand; } //We need to be running!
		//[9]=Amount of sectors, [2-5]=LBA address, LBA mid/high=2048.
		LBA = (((((ATA[channel].Drive[drive].ATAPI_PACKET[2]<<8) | ATA[channel].Drive[drive].ATAPI_PACKET[3])<<8)| ATA[channel].Drive[drive].ATAPI_PACKET[4]) << 8)| ATA[channel].Drive[drive].ATAPI_PACKET[5]; //The LBA address!
		ATA[channel].datasize = (ATA[channel].Drive[drive].ATAPI_PACKET[7]<<1)|(ATA[channel].Drive[drive].ATAPI_PACKET[8]); //How many sectors to transfer
		if (ATA[channel].Drive[drive].ATAPI_PACKET[0]==0xA8) //Extended sectors to transfer?
		{
			ATA[channel].datasize = (ATA[channel].Drive[drive].ATAPI_PACKET[6]<<3) | (ATA[channel].Drive[drive].ATAPI_PACKET[7]<<2) | (ATA[channel].Drive[drive].ATAPI_PACKET[8] << 1) | (ATA[channel].Drive[drive].ATAPI_PACKET[9]); //How many sectors to transfer
		}

		if ((LBA>disk_size) || ((LBA+ATA[channel].datasize-1)>disk_size)){abortreason=5;additionalsensecode=0x21;goto ATAPI_invalidcommand;} //Error out when invalid sector!
		
		ATA[channel].datapos = 0; //Start of data!
		ATA[channel].datablock = 0x800; //We're refreshing after this many bytes! Use standard CD-ROM 2KB blocks!
		ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_LBA = LBA; //The LBA to use!
		if (ATAPI_readsector(channel)) //Sector read?
		{
			ATA_IRQ(channel,ATA_activeDrive(channel)); //Raise an IRQ: we're needing attention!
		}
		break;
	case 0x25: //Read CD-ROM capacity(Mandatory)?
		if (!is_mounted(ATA_Drives[channel][drive])){abortreason=2;additionalsensecode=0x3A;goto ATAPI_invalidcommand;} //Error out if not present!
		if (!ATA[channel].Drive[ATA_activeDrive(channel)].isSpinning) { abortreason = 2;additionalsensecode = 0x4;goto ATAPI_invalidcommand; } //We need to be running!
		ATA[channel].datapos = 0; //Start of data!
		ATA[channel].datablock = 8; //Size of a block of information to transfer!
		ATA[channel].datasize = 1; //Number of blocks of information to transfer!
		ATA[channel].data[0] = (disk_size&0xFF);
		ATA[channel].data[1] = ((disk_size>>8) & 0xFF);
		ATA[channel].data[2] = ((disk_size>>16) & 0xFF);
		ATA[channel].data[3] = ((disk_size>>24) & 0xFF);
		ATA[channel].data[4] = 0;
		ATA[channel].data[5] = 8;
		ATA[channel].data[6] = 0;
		ATA[channel].data[7] = 0; //We're 4096 byte sectors!
		ATA[channel].commandstatus = 1; //Transferring data IN!
		ATAPI_giveresultsize(channel,ATA[channel].datablock*ATA[channel].datasize); //Result size!
		ATA_IRQ(channel,ATA_activeDrive(channel)); //Raise an IRQ: we're finished!
		break;
	default:
		dolog("ATAPI","Executing unknown SCSI command: %02X", ATA[channel].Drive[drive].ATAPI_PACKET[0]); //Error: invalid command!
		ATAPI_invalidcommand:
		ATAPI_giveresultsize(channel,0); //No result size!
		ATA[channel].Drive[drive].ERRORREGISTER = 4|(abortreason<<4); //Reset error register! This also contains a copy of the Sense Key!
		ATAPI_SENSEPACKET_SENSEKEYW(channel,drive,abortreason); //Reason of the error
		ATAPI_SENSEPACKET_ADDITIONALSENSECODEW(channel,drive,additionalsensecode); //Extended reason code
		ATAPI_SENSEPACKET_ERRORCODEW(channel,drive,0x70); //Default error code?
		ATAPI_SENSEPACKET_ADDITIONALSENSELENGTHW(channel,drive,8); //Additional Sense Length = 8?
		ATAPI_SENSEPACKET_INFORMATION0W(channel,drive,0); //No info!
		ATAPI_SENSEPACKET_INFORMATION1W(channel,drive,0); //No info!
		ATAPI_SENSEPACKET_INFORMATION2W(channel,drive,0); //No info!
		ATAPI_SENSEPACKET_INFORMATION3W(channel,drive,0); //No info!
		ATAPI_SENSEPACKET_COMMANDSPECIFICINFORMATION0W(channel,drive,0); //No command specific information?
		ATAPI_SENSEPACKET_COMMANDSPECIFICINFORMATION1W(channel,drive,0); //No command specific information?
		ATAPI_SENSEPACKET_COMMANDSPECIFICINFORMATION2W(channel,drive,0); //No command specific information?
		ATAPI_SENSEPACKET_COMMANDSPECIFICINFORMATION3W(channel,drive,0); //No command specific information?
		ATAPI_SENSEPACKET_VALIDW(channel,drive,1); //We're valid!
		ATA[channel].Drive[drive].STATUSREGISTER = 0; //Clear status!
		ATA_STATUSREGISTER_DRIVEREADYW(channel,drive,1); //Ready!
		ATA_STATUSREGISTER_ERRORW(channel,drive,1); //Ready!
		//Reset of the status register is 0!
		ATA[channel].commandstatus = 0xFF; //Move to error mode!
		ATA_IRQ(channel, ATA_activeDrive(channel));
		aborted = 1; //We're aborted!
		break;
	}
	if (aborted==0) {
		ATAPI_SENSEPACKET_SENSEKEYW(channel,drive,0);
		ATAPI_SENSEPACKET_ADDITIONALSENSECODEW(channel,drive,0);
		ATAPI_SENSEPACKET_VALIDW(channel,drive,0); //Not valid anymore!
	} //Clear reason on success!
}

OPTINLINE void giveATAPISignature(byte channel)
{
	ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectorcount = 0x01;
	ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh = 0xEB;
	ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow = 0x14;
	ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectornumber = 0x01;
}

OPTINLINE void giveATASignature(byte channel)
{
	ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectorcount = 0x01;
	ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh = 0x00;
	ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow = 0x00;
	ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectornumber = 0x01;
}

void ATA_reset(byte channel)
{
	if ((ATA_Drives[channel][ATA_activeDrive(channel)] >= CDROM0)) //CD-ROM specified?
	{
		giveATAPISignature(channel); //We're a CD-ROM, give ATAPI signature!
	}
	else //Normal IDE harddrive?
	{
		giveATASignature(channel); //We're a harddisk, give ATA signature!
	}
	//Clear errors!
	ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER = 0x00; //No error!
	//Clear Drive/Head register, leaving the specified drive as it is!
	ATA_DRIVEHEAD_HEADW(channel,ATA_activeDrive(channel),0); //What head?
	ATA_DRIVEHEAD_LBAMODE_2W(channel,ATA_activeDrive(channel),0); //LBA mode?
	ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.drivehead |= 0xA0; //Always 1!
	ATA[channel].commandstatus = 3; //We're busy waiting!
	ATA[channel].resetTiming = ATA_RESET_TIMEOUT; //How long to wait in reset!
}

OPTINLINE void ATA_executeCommand(byte channel, byte command) //Execute a command!
{
#ifdef ATA_LOG
	dolog("ATA", "ExecuteCommand: %02X", command); //Execute this command!
#endif
	ATA[channel].longop = 0; //Default: no long operation!
	int drive;
	byte temp;
	uint_32 disk_size; //For checking against boundaries!
	switch (command) //What command?
	{
	case 0x90: //Execute drive diagnostic (Mandatory)?
#ifdef ATA_LOG
		dolog("ATA", "DIAGNOSTICS:%i,%i=%02X", channel, ATA_activeDrive(channel), command);
#endif
		ATA[channel].Drive[0].ERRORREGISTER = 0x1; //OK!
		ATA[channel].Drive[1].ERRORREGISTER = 0x1; //OK!
		ATA_STATUSREGISTER_ERRORW(channel,0,0); //Not an error!
		ATA_STATUSREGISTER_ERRORW(channel,1,0); //Not an error!
		ATA[channel].commandstatus = 0; //Reset status!
		ATA_IRQ(channel, ATA_activeDrive(channel)); //IRQ!
		break;
	case 0xDB: //Acnowledge media change?
#ifdef ATA_LOG
		dolog("ATA", "ACNMEDIACHANGE:%i,%i=%02X", channel, ATA_activeDrive(channel), command);
#endif
		if ((ATA_Drives[channel][ATA_activeDrive(channel)] >= CDROM0)) goto invalidcommand; //Special action for CD-ROM drives?
		switch (ATA_Drives[channel][ATA_activeDrive(channel)]) //What kind of drive?
		{
		case CDROM0:
		case CDROM1: //CD-ROM?
			ATA_ERRORREGISTER_MEDIACHANGEDW(channel,ATA_activeDrive(channel),0); //Not changed anymore!
			ATA[channel].commandstatus = 0; //Reset status!
			break;
		default:
			goto invalidcommand;
		}
		break;
	case 0x10:
	case 0x11:
	case 0x12:
	case 0x13:
	case 0x14:
	case 0x15:
	case 0x16:
	case 0x17:
	case 0x18:
	case 0x19:
	case 0x1A:
	case 0x1B:
	case 0x1C:
	case 0x1D:
	case 0x1E:
	case 0x1F: //Recalibrate?
#ifdef ATA_LOG
		dolog("ATA", "RECALIBRATE:%i,%i=%02X", channel, ATA_activeDrive(channel), command);
#endif
		if ((ATA_Drives[channel][ATA_activeDrive(channel)] >= CDROM0)) goto invalidcommand; //Special action for CD-ROM drives?
		ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER = 0; //Default to no error!
		if (is_mounted(ATA_Drives[channel][ATA_activeDrive(channel)]) && (ATA_Drives[channel][ATA_activeDrive(channel)]>=HDD0) && (ATA_Drives[channel][ATA_activeDrive(channel)]<=HDD1)) //Gotten drive and is a hard disk?
		{
#ifdef ATA_LOG
			dolog("ATA", "Recalibrated!");
#endif
			temp = (ATA[channel].command & 0xF); //???
			ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh = ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow = 0; //Clear cylinder #!
			ATA_STATUSREGISTER_DRIVESEEKCOMPLETEW(channel,ATA_activeDrive(channel),1); //We've completed seeking!
			ATA_STATUSREGISTER_ERRORW(channel,ATA_activeDrive(channel),0); //Not an error!
			ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER = 0; //No error!
			ATA[channel].commandstatus = 0; //Reset status!
			ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise the IRQ!
		}
		else
		{
			ATA_STATUSREGISTER_DRIVESEEKCOMPLETEW(channel,ATA_activeDrive(channel),0); //We've not completed seeking!
			ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER = 0; //Track 0 couldn't be found!
			ATA_ERRORREGISTER_TRACK0NOTFOUNDW(channel,ATA_activeDrive(channel),1); //Track 0 couldn't be found!
			ATA[channel].commandstatus = 0xFF; //Error!
		}
		break;
	case 0x70:
	case 0x71:
	case 0x72:
	case 0x73:
	case 0x74:
	case 0x75:
	case 0x76:
	case 0x77:
	case 0x78:
	case 0x79:
	case 0x7A:
	case 0x7B:
	case 0x7C:
	case 0x7D:
	case 0x7E:
	case 0x7F: //Seek?
#ifdef ATA_LOG
		dolog("ATA", "SEEK:%i,%i=%02X", channel, ATA_activeDrive(channel), command);
#endif
		if ((ATA_Drives[channel][ATA_activeDrive(channel)] >= CDROM0)) goto invalidcommand; //Special action for CD-ROM drives?
		temp = (command & 0xF); //The head to select!
		if (((ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh << 8) | ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow) < ATA[channel].Drive[ATA_activeDrive(channel)].driveparams[54]) //Cylinder correct?
		{
			if (temp < ATA[channel].Drive[ATA_activeDrive(channel)].driveparams[55]) //Head within range?
			{
#ifdef ATA_LOG
				dolog("ATA", "Seeked!");
#endif
				ATA[channel].Drive[ATA_activeDrive(channel)].STATUSREGISTER = 0; //No error!
				ATA_STATUSREGISTER_DRIVESEEKCOMPLETEW(channel,ATA_activeDrive(channel),1); //We've completed seeking!
				ATA_STATUSREGISTER_ERRORW(channel,ATA_activeDrive(channel),0); //Not an error!
				ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER = 0; //No error!
				ATA[channel].commandstatus = 0; //Reset status!
				ATA_DRIVEHEAD_HEADW(channel,ATA_activeDrive(channel),(command & 0xF)); //Select the following head!
				ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise the IRQ!
			}
			else goto invalidcommand; //Error out!
		}
		else goto invalidcommand; //Error out!
		break;
	case 0x22: //Read long (w/retry, ATAPI Mandatory)?
	case 0x23: //Read long (w/o retry, ATAPI Mandatory)?
		ATA[channel].longop = 1; //Long operation!
	case 0x20: //Read sector(s) (w/retry, ATAPI Mandatory)?
	case 0x21: //Read sector(s) (w/o retry, ATAPI Mandatory)?
#ifdef ATA_LOG
		dolog("ATA", "READ(long:%i):%i,%i=%02X", ATA[channel].longop,channel, ATA_activeDrive(channel), command);
#endif
		if ((ATA_Drives[channel][ATA_activeDrive(channel)] >= CDROM0)) //Special action for CD-ROM drives?
		{
			//Enter reserved ATAPI result!
			ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER = 1; //Passed!
			giveATAPISignature(channel);
			goto invalidcommand_noerror; //Execute an invalid command result!
		}
		ATA[channel].datasize = ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectorcount; //Load sector count!
		if (ATA_DRIVEHEAD_LBAMODER(channel,ATA_activeDrive(channel))) //Are we in LBA mode?
		{
			ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address = read_LBA(channel); //The LBA address!
		}
		else //Normal CHS address?
		{
			ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address = ATA_CHS2LBA(channel,ATA_activeDrive(channel),
				((ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh << 8) | (ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow)),
				ATA_DRIVEHEAD_HEADR(channel,ATA_activeDrive(channel)),
				ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectornumber); //The LBA address based on the CHS address!

		}
		ATA_STATUSREGISTER_ERRORW(channel,ATA_activeDrive(channel),0); //Not an error!
		if (ATA_readsector(channel,command)) //OK?
		{
			ATA_IRQ(channel, ATA_activeDrive(channel)); //Give our requesting IRQ!
		}
		break;
	case 0x40: //Read verify sector(s) (w/retry)?
	case 0x41: //Read verify sector(s) (w/o retry)?
		if ((ATA_Drives[channel][ATA_activeDrive(channel)] >= CDROM0)) goto invalidcommand; //Special action for CD-ROM drives?
		disk_size = ((ATA[channel].Drive[ATA_activeDrive(channel)].driveparams[61] << 16) | ATA[channel].Drive[ATA_activeDrive(channel)].driveparams[60]); //The size of the disk in sectors!
		ATA[channel].datasize = ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectorcount; //Load sector count!
		if (ATA_DRIVEHEAD_LBAMODER(channel,ATA_activeDrive(channel))) //Are we in LBA mode?
		{
			ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address = read_LBA(channel); //The LBA address!
		}
		else //Normal CHS address?
		{
			ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address = ATA_CHS2LBA(channel, ATA_activeDrive(channel),
				((ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh << 8) | (ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow)),
				ATA_DRIVEHEAD_HEADR(channel,ATA_activeDrive(channel)),
				ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectornumber); //The LBA address based on the CHS address!

		}
		ATA_STATUSREGISTER_ERRORW(channel,ATA_activeDrive(channel),0); //Not an error!
		nextverification: //Verify the next sector!
		if (ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address<=disk_size) //OK?
		{
			++ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address; //Next sector!
			if (--ATA[channel].datasize) //Still left?
			{
				goto nextverification; //Verify the next sector!
			}
		}
		else //Out of range?
		{
			ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER = 0; //Reset error register!
			ATA_ERRORREGISTER_IDMARKNOTFOUNDW(channel,ATA_activeDrive(channel),1); //Not found!
			ATA_STATUSREGISTER_ERRORW(channel,ATA_activeDrive(channel),1); //Error!
			ATA_updatesector(channel); //Update the current sector!
			ATA[channel].commandstatus = 0xFF; //Error!
		}
		if (!ATA_STATUSREGISTER_ERRORR(channel,ATA_activeDrive(channel))) //Finished OK?
		{
			ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise the OK IRQ!
		}
		break;
	case 0x32: //Write long (w/retry)?
	case 0x33: //Write long (w/o retry)?
		ATA[channel].longop = 1; //Long operation!
	case 0x30: //Write sector(s) (w/retry)?
	case 0x31: //Write sectors (w/o retry)?
		if ((ATA_Drives[channel][ATA_activeDrive(channel)] >= CDROM0)) goto invalidcommand; //Special action for CD-ROM drives?
#ifdef ATA_LOG
		dolog("ATA", "WRITE(LONG:%i):%i,%i=%02X; Length=%02X", ATA[channel].longop, channel, ATA_activeDrive(channel), command, ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectorcount);
#endif
		ATA[channel].datasize = ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectorcount; //Load sector count!
		if (ATA_DRIVEHEAD_LBAMODER(channel,ATA_activeDrive(channel))) //Are we in LBA mode?
		{
			ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address = read_LBA(channel); //The LBA address!
		}
		else //Normal CHS address?
		{
			ATA[channel].Drive[ATA_activeDrive(channel)].current_LBA_address = ATA_CHS2LBA(channel, ATA_activeDrive(channel),
				((ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh << 8) | (ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow)),
				ATA_DRIVEHEAD_HEADR(channel,ATA_activeDrive(channel)),
				ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectornumber); //The LBA address based on the CHS address!

		}
		ATA_STATUSREGISTER_ERRORW(channel,ATA_activeDrive(channel),0); //Not an error!
		ATA_IRQ(channel, ATA_activeDrive(channel)); //Give our requesting IRQ!
		ATA[channel].commandstatus = 2; //Transferring data OUT!
		ATA[channel].datablock = 0x200; //We're writing 512 bytes to our output at a time!
		ATA[channel].datapos = 0; //Start at the beginning of the sector buffer!
		ATA[channel].command = command; //We're executing this command!
		break;
	case 0x91: //Initialise device parameters?
#ifdef ATA_LOG
		dolog("ATA", "INITDRVPARAMS:%i,%i=%02X", channel, ATA_activeDrive(channel), command);
#endif
		if ((ATA_Drives[channel][ATA_activeDrive(channel)] >= CDROM0)) goto invalidcommand; //Special action for CD-ROM drives?
		ATA[channel].commandstatus = 0; //Requesting command again!
		ATA[channel].Drive[ATA_activeDrive(channel)].driveparams[55] = (ATA_DRIVEHEAD_HEADR(channel,ATA_activeDrive(channel)) + 1); //Set the current maximum head!
		ATA[channel].Drive[ATA_activeDrive(channel)].driveparams[56] = (ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectorcount); //Set the current sectors per track!
		ATA_updateCapacity(channel,ATA_activeDrive(channel)); //Update the capacity!
		ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER = 0; //No errors!
		ATA_STATUSREGISTER_ERRORW(channel,ATA_activeDrive(channel),0); //Not an error!
		break;
	case 0xA1: //ATAPI: IDENTIFY PACKET DEVICE (ATAPI Mandatory)!
		if ((ATA_Drives[channel][ATA_activeDrive(channel)]>=CDROM0) && ATA_Drives[channel][ATA_activeDrive(channel)]) //CDROM drive?
		{
			ATA[channel].command = 0xA1; //We're running this command!
			goto CDROMIDENTIFY; //Execute CDROM identification!
		}
		goto invalidcommand; //We're an invalid command: we're not a CDROM drive!
	case 0xEC: //Identify device (Mandatory)?
#ifdef ATA_LOG
		dolog("ATA", "IDENTIFY:%i,%i=%02X", channel, ATA_activeDrive(channel), command);
#endif
		if (!ATA_Drives[channel][ATA_activeDrive(channel)]) goto invalidcommand; //No drive errors out!
		if (ATA_Drives[channel][ATA_activeDrive(channel)] >= CDROM0) //Special action for CD-ROM drives?
		{
			//Enter reserved ATAPI result!
			ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER = 1; //Passed!
			giveATAPISignature(channel);
			goto invalidcommand_noerror; //Execute an invalid command result!
		}
		ATA[channel].command = 0xEC; //We're running this command!
		CDROMIDENTIFY:
		memcpy(&ATA[channel].data, &ATA[channel].Drive[ATA_activeDrive(channel)].driveparams, sizeof(ATA[channel].Drive[ATA_activeDrive(channel)].driveparams)); //Set drive parameters currently set!
		ATA[channel].Drive[ATA_activeDrive(channel)].STATUSREGISTER = 0; //Clear any errors!
		ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER = 0; //No errors!
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow = 0; //Needs to be 0 to detect!
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh = 0; //Needs to be 0 to detect!
		ATA_STATUSREGISTER_ERRORW(channel,ATA_activeDrive(channel),0); //Not an error!
		ATA_STATUSREGISTER_DRIVESEEKCOMPLETEW(channel,ATA_activeDrive(channel),1); //We have data now!
		//Finish up!
		ATA[channel].datapos = 0; //Initialise data position for the result!
		ATA[channel].datablock = sizeof(ATA[channel].Drive[ATA_activeDrive(channel)].driveparams); //512 byte result!
		ATA[channel].commandstatus = 1; //We're requesting data to be read!
		ATA_IRQ(channel, ATA_activeDrive(channel)); //Execute an IRQ from us!
		break;
	case 0xA0: //ATAPI: PACKET (ATAPI mandatory)!
		if ((ATA_Drives[channel][ATA_activeDrive(channel)] < CDROM0) || !ATA_Drives[channel][ATA_activeDrive(channel)]) goto invalidcommand; //HDD/invalid disk errors out!
		ATA[channel].command = 0xA0; //We're sending a ATAPI packet!
		ATA[channel].datablock = 12; //We're receiving 12 bytes for the ATAPI packet!
		ATA[channel].datapos = 0; //Initialise data position for the packet!
		ATA[channel].commandstatus = 2; //We're requesting data to be written!
		ATA[channel].Drive[ATA_activeDrive(channel)].STATUSREGISTER = 0; //Clear any errors!
		ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER = 0; //No errors!
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow = 12; //We're requesting...
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh = 0; //12 bytes of data to be transferred!
		ATA[channel].Drive[ATA_activeDrive(channel)].ATAPI_processingPACKET = 1; //We're processing an ATAPI/SCSI packet!
		ATA_IRQ(channel,ATA_activeDrive(channel)); //Execute an IRQ: we're ready to receive the packet!
		break;
	case 0xDA: //Get media status?
#ifdef ATA_LOG
		dolog("ATA", "GETMEDIASTATUS:%i,%i=%02X", channel, ATA_activeDrive(channel), command);
#endif
		if ((ATA_Drives[channel][ATA_activeDrive(channel)] >= CDROM0)) goto invalidcommand; //Special action for CD-ROM drives?
		if (ATA_Drives[channel][ATA_activeDrive(channel)] >= CDROM0) //CD-ROM drive?
		{
			drive = ATA_Drives[channel][ATA_activeDrive(channel)]; //Load the drive identifier!
			if (is_mounted(drive)) //Drive inserted?
			{
				ATA_ERRORREGISTER_UNCORRECTABLEDATAW(channel,ATA_activeDrive(channel),drivereadonly(drive)); //Are we read-only!
			}
			else
			{
				ATA_ERRORREGISTER_UNCORRECTABLEDATAW(channel,ATA_activeDrive(channel),0); //Are we read-only!
			}
			ATA_ERRORREGISTER_MEDIACHANGEDW(channel,ATA_activeDrive(channel),0); //Not anymore!
			ATA_STATUSREGISTER_ERRORW(channel,ATA_activeDrive(channel),0); //Not an error!
			ATA_IRQ(channel, ATA_activeDrive(channel)); //Raise IRQ!
			ATA[channel].commandstatus = 0; //Reset status!
		}
		else goto invalidcommand;
		break;
	case 0xEF: //Set features (Mandatory)?
#ifdef ATA_LOG
		dolog("ATA", "Set features:%i,%i=%02X", channel, ATA_activeDrive(channel), ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.features); //Set these features!
#endif
		switch (ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.features) //What features to set?
		{
		case 0x01: //Enable 8-bit data transfers!
			ATA[channel].Drive[ATA_activeDrive(channel)].Enable8BitTransfers = 1; //Enable 8-bit transfers!
			break;
		case 0x81: //Disable 8-bit data transfers!
			ATA[channel].Drive[ATA_activeDrive(channel)].Enable8BitTransfers = 0; //Disable 8-bit transfers!
			break;
		case 0x02: //Enable write cache!
			//OK! Ignore!
			break;
		case 0x82: //Disable write cache!
			//OK! Ignore!
			break;
		default: //Invalid feature!
#ifdef ATA_LOG
			dolog("ATA", "Invalid feature set: %02X", ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.features);
#endif
			goto invalidcommand; //Error out!
			break;
		}
		ATA[channel].commandstatus = 0; //Reset command status!
		ATA[channel].Drive[ATA_activeDrive(channel)].STATUSREGISTER = 0; //Reset data register!
		break;
	case 0x00: //NOP (ATAPI Mandatory)?
		break;
	case 0x08: //DEVICE RESET(ATAPI Mandatory)?
		if (!(ATA_Drives[channel][ATA_activeDrive(channel)] >= CDROM0)) //ATA device? Unsupported!
		{
			#ifdef ATA_LOG
			dolog("ATA", "Invalid ATAPI on ATA drive command: %02X", command);
			#endif
			goto invalidcommand;
		}
		ATA[channel].commandstatus = 0; //Reset command status!
		ATA[channel].command = 0; //Full reset!
		ATA_reset(channel); //Reset the channel!
		break;
	case 0xDC: //BIOS - post-boot?
	case 0xDD: //BIOS - pre-boot?
	case 0x50: //Format track?
	case 0x97:
	case 0xE3: //Idle?
	case 0x95:
	case 0xE1: //Idle immediate?
	case 0xE4: //Read buffer?
	case 0xC8: //Read DMA (w/retry)?
	case 0xC9: //Read DMA (w/o retry)?
	case 0xC4: //Read multiple?
	case 0xC6: //Set multiple mode?
	case 0x99:
	case 0xE6: //Sleep?
	case 0x96:
	case 0xE2: //Standby?
	case 0x94:
	case 0xE0: //Standby immediate?
	case 0xE8: //Write buffer?
	case 0xCA: //Write DMA (w/retry)?
	case 0xCB: //Write DMA (w/o retry)?
	case 0xC5: //Write multiple?
	case 0xE9: //Write same?
	case 0x3C: //Write verify?
	default: //Unknown command?
		//Invalid command?
		invalidcommand:
#ifdef ATA_LOG
		dolog("ATA", "INVALIDCOMMAND:%i,%i=%02X", channel, ATA_activeDrive(channel), command);
#endif
		ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER = 4; //Reset error register!
		ATA[channel].Drive[ATA_activeDrive(channel)].STATUSREGISTER = 0; //Clear status!
		ATA_STATUSREGISTER_ERRORW(channel,ATA_activeDrive(channel),1); //Ready!
		invalidcommand_noerror:
		ATA[channel].Drive[ATA_activeDrive(channel)].STATUSREGISTER = 0; //Clear status!
		ATA_STATUSREGISTER_DRIVEREADYW(channel,ATA_activeDrive(channel),1); //Ready!
		//Reset of the status register is 0!
		ATA[channel].commandstatus = 0xFF; //Move to error mode!
		ATA_IRQ(channel, ATA_activeDrive(channel));
		break;
	}
}

OPTINLINE void ATA_updateStatus(byte channel)
{
	switch (ATA[channel].commandstatus) //What command status?
	{
	case 0: //Ready for command?
		ATA_STATUSREGISTER_DRIVEREADYW(channel,ATA_activeDrive(channel),ATA[channel].driveselectTiming?0:1); //We're ready to process a command!
		break;
	case 1: //Transferring data IN?
		ATA_STATUSREGISTER_BUSYW(channel,ATA_activeDrive(channel),0); //Not busy! You can write to the CBRs!
		ATA_STATUSREGISTER_DRIVEREADYW(channel,ATA_activeDrive(channel),ATA[channel].driveselectTiming?0:1); //We're ready to process a command!
		ATA_STATUSREGISTER_DATAREQUESTREADYW(channel,ATA_activeDrive(channel),1); //We're requesting data to transfer!
		break;
	case 2: //Transferring data OUT?
		ATA_STATUSREGISTER_BUSYW(channel,ATA_activeDrive(channel),0); //Not busy! You can write to the CBRs!
		ATA_STATUSREGISTER_DRIVEREADYW(channel,ATA_activeDrive(channel),ATA[channel].driveselectTiming?0:1); //We're ready to process a command!
		ATA_STATUSREGISTER_DATAREQUESTREADYW(channel,ATA_activeDrive(channel),1); //We're requesting data to transfer!
		break;
	case 3: //Busy waiting?
		ATA_STATUSREGISTER_BUSYW(channel,ATA_activeDrive(channel),1); //Busy! You can write to the CBRs!
		ATA_STATUSREGISTER_DRIVEREADYW(channel,ATA_activeDrive(channel),0); //We're not ready to process a command!
		ATA_STATUSREGISTER_DATAREQUESTREADYW(channel,ATA_activeDrive(channel),0); //We're requesting data to transfer!
		break;
	default: //Unknown?
	case 0xFF: //Error?
		ATA_STATUSREGISTER_ERRORW(channel,ATA_activeDrive(channel),1); //Error!
		ATA[channel].commandstatus = 0; //Reset command status: we've reset!
		break;
	}
}

OPTINLINE void ATA_writedata(byte channel, byte value)
{
	if (!ATA_Drives[channel][ATA_activeDrive(channel)]) //Invalid drive?
	{
		return; //OK!
	}
	switch (ATA[channel].commandstatus) //Current status?
	{
	case 2: //DATA OUT?
		ATA_dataOUT(channel,value); //Read data!
		break;
	default: //Unknown status?
		break;
	}
}

byte outATA16(word port, word value)
{
	byte channel = 0; //What channel?
	if (port != getPORTaddress(channel)) //Primary channel?
	{
		channel = 1; //Try secondary channel!
		if (port != getPORTaddress(channel)) //Secondary channel?
		{
			return 0; //Not our port?
		}
	}
	if (ATA[channel].Drive[ATA_activeDrive(channel)].Enable8BitTransfers) return 0; //We're only 8-bit data transfers!
	ATA_writedata(channel, (value&0xFF)); //Write the data low!
	ATA_writedata(channel, ((value >> 8) & 0xFF)); //Write the data high!
	return 1;
}

byte outATA8(word port, byte value)
{
	byte pendingreset = 0;
	byte channel = 0; //What channel?
	if ((port<getPORTaddress(channel)) || (port>(getPORTaddress(channel) + 0x7))) //Primary channel?
	{
		if (port == (getControlPORTaddress(channel))) goto port3_write;
		channel = 1; //Try secondary channel!
		if ((port<getPORTaddress(channel)) || (port>(getPORTaddress(channel) + 0x7))) //Secondary channel?
		{
			if (port == (getControlPORTaddress(channel))) goto port3_write;
			return 0; //Not our port?
		}
	}
	port -= getPORTaddress(channel); //Get the port from the base!
	switch (port) //What port?
	{
	case 0: //DATA?
		if (ATA[channel].Drive[ATA_activeDrive(channel)].Enable8BitTransfers) //Enabled 8-bit transfers?
		{
			ATA_writedata(channel, value); //Write the data!
			return 1; //We're enabled!
		}
		return 0; //We're non-existant!
		break;
	case 1: //Features?
#ifdef ATA_LOG
		dolog("ATA", "Feature register write: %02X %i.%i", value,channel,ATA_activeDrive(channel));
#endif
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.features = value; //Use the set data! Ignore!
		return 1; //OK!
		break;
	case 2: //Sector count?
#ifdef ATA_LOG
		dolog("ATA", "Sector count write: %02X %i.%i", value,channel, ATA_activeDrive(channel));
#endif
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectorcount = value; //Set sector count!
		return 1; //OK!
		break;
	case 3: //Sector number?
#ifdef ATA_LOG
		dolog("ATA", "Sector number write: %02X %i.%i", value, channel, ATA_activeDrive(channel));
#endif
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectornumber = value; //Set sector number!
		return 1; //OK!
		break;
	case 4: //Cylinder low?
#ifdef ATA_LOG
		dolog("ATA", "Cylinder low write: %02X %i.%i", value, channel, ATA_activeDrive(channel));
#endif
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow = value; //Set cylinder low!
		return 1; //OK!
		break;
	case 5: //Cylinder high?
#ifdef ATA_LOG
		dolog("ATA", "Cylinder high write: %02X %i.%i", value, channel, ATA_activeDrive(channel));
#endif
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh = value; //Set cylinder high!
		return 1; //OK!
		break;
	case 6: //Drive/head?
#ifdef ATA_LOG
		dolog("ATA", "Drive/head write: %02X %i.%i", value, channel, ATA_activeDrive(channel));
#endif
		ATA[channel].activedrive = (value >> 4) & 1; //The active drive!
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.drivehead = value; //Set drive head!
		ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh = ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow = 0; //We're an PATA device!
		ATA[channel].driveselectTiming = ATA_DRIVESELECT_TIMEOUT; //Drive select timing to use!
		return 1; //OK!
		break;
	case 7: //Command?
		ATA_removeIRQ(channel,ATA_activeDrive(channel)); //Lower the IRQ by writes too, not just reads!
		ATA_executeCommand(channel,value); //Execute a command!
		return 1; //OK!
		break;
	default: //Unsupported!
		break;
	}
	return 0; //Safety!
port3_write: //Special port #3?
	port -= getControlPORTaddress(channel); //Get the port from the base!
	if (!ATA_Drives[channel][ATA_activeDrive(channel)]) //Invalid drive?
	{
		return 1; //OK!
	}
	switch (port) //What port?
	{
	case 0: //Control register?
#ifdef ATA_LOG
		dolog("ATA", "Control register write: %02X %i.%i",value, channel, ATA_activeDrive(channel));
#endif
		if (DRIVECONTROLREGISTER_SRSTR(channel)==0) pendingreset = 1; //We're pending reset!
		ATA[channel].DriveControlRegister = value; //Set the data!
		if (DRIVECONTROLREGISTER_SRSTR(channel) && pendingreset) //Pending reset?
		{
			//We cause all drives to reset on this channel!
			ATA_removeIRQ(channel,0); //Resetting lowers the IRQ when transitioning from 0 to 1!
			ATA_removeIRQ(channel,1); //Resetting lowers the IRQ when transitioning from 0 to 1!
			ATA_reset(channel); //Reset the specified channel!
		}
		return 1; //OK!
		break;
	default: //Unsupported!
		break;
	}
	return 0; //Unsupported!
}

OPTINLINE void ATA_readdata(byte channel, byte *result)
{
	if (!ATA_Drives[channel][ATA_activeDrive(channel)])
	{
		*result = 0; //No result!
		return; //Abort!
	}
	switch (ATA[channel].commandstatus) //Current status?
	{
	case 1: //DATA IN?
		*result = ATA_dataIN(channel); //Read data!
		break;
	default: //Unknown status?
		*result = 0; //Unsupported for now!
		break;
	}
}

byte inATA16(word port, word *result)
{
	byte channel = 0; //What channel?
	if (port!=getPORTaddress(channel)) //Primary channel?
	{
		channel = 1; //Try secondary channel!
		if (port!=getPORTaddress(channel)) //Secondary channel?
		{
			return 0; //Not our port?
		}
	}
	if (ATA[channel].Drive[ATA_activeDrive(channel)].Enable8BitTransfers) return 0; //We're only 8-bit data transfers!
	byte buffer;
	word resultbuffer;
	ATA_readdata(channel, &buffer); //Read the low data!
	resultbuffer = buffer; //Load the low byte!
	ATA_readdata(channel, &buffer); //Read the high data!
	resultbuffer |= (buffer << 8); //Load the high byte!
	*result = resultbuffer; //Set the result!
	return 1;
}

byte inATA8(word port, byte *result)
{
	byte channel = 0; //What channel?
	if ((port<getPORTaddress(channel)) || (port>(getPORTaddress(channel) + 0x7))) //Primary channel?
	{
		if ((port >= (getControlPORTaddress(channel))) && (port <= (getControlPORTaddress(channel)+1))) goto port3_read;
		channel = 1; //Try secondary channel!
		if ((port<getPORTaddress(channel)) || (port>(getPORTaddress(channel) + 0x7))) //Secondary channel?
		{
			if ((port >= (getControlPORTaddress(channel))) && (port <= (getControlPORTaddress(channel)+1))) goto port3_read;
			return 0; //Not our port?
		}
	}
	if (!ATA_Drives[channel][ATA_activeDrive(channel)]) //Invalid drive?
	{
		*result = 0; //Give 0: we're not present!
		return 1; //OK!
	}
	port -= getPORTaddress(channel); //Get the port from the base!
	switch (port) //What port?
	{
	case 0: //DATA?
		if (ATA[channel].Drive[ATA_activeDrive(channel)].Enable8BitTransfers) //Enabled 8-bit transfers?
		{
			ATA_readdata(channel, result); //Read the data!
			return 1; //We're enabled!
		}
		return 0; //We're 16-bit only!
		break;
	case 1: //Error register?
		*result = ATA[channel].Drive[ATA_activeDrive(channel)].ERRORREGISTER; //Error register!
#ifdef ATA_LOG
		dolog("ATA", "Error register read: %02X %i.%i", *result, channel, ATA_activeDrive(channel));
#endif
		return 1;
		break;
	case 2: //Sector count?
		*result = ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectorcount; //Get sector count!
#ifdef ATA_LOG
		dolog("ATA", "Sector count register read: %02X %i.%i", *result, channel, ATA_activeDrive(channel));
#endif
		return 1;
		break;
	case 3: //Sector number?
		*result = ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.sectornumber; //Get sector number!
#ifdef ATA_LOG
		dolog("ATA", "Sector number register read: %02X %i.%i", *result, channel, ATA_activeDrive(channel));
#endif
		return 1; //OK!
		break;
	case 4: //Cylinder low?
		*result = ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderlow; //Get cylinder low!
#ifdef ATA_LOG
		dolog("ATA", "Cylinder low read: %02X %i.%i", *result, channel, ATA_activeDrive(channel));
#endif
		return 1; //OK!
		break;
	case 5: //Cylinder high?
		*result = ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.cylinderhigh; //Get cylinder high!
#ifdef ATA_LOG
		dolog("ATA", "Cylinder high read: %02X %i.%i", *result, channel, ATA_activeDrive(channel));
#endif
		return 1; //OK!
		break;
	case 6: //Drive/head?
		*result = ATA[channel].Drive[ATA_activeDrive(channel)].PARAMETERS.drivehead; //Get drive/head!
#ifdef ATA_LOG
		dolog("ATA", "Drive/head register read: %02X %i.%i", *result, channel, ATA_activeDrive(channel));
#endif
		return 1; //OK!
		break;
	case 7: //Status?
		ATA_updateStatus(channel); //Update the status register if needed!
		ATA_removeIRQ(channel,ATA_activeDrive(channel)); //Acnowledge IRQ!
		*result = ATA[channel].Drive[ATA_activeDrive(channel)].STATUSREGISTER; //Get status!
		ATA_STATUSREGISTER_DRIVEWRITEFAULTW(channel,ATA_activeDrive(channel),0); //Reset write fault flag!
#ifdef ATA_LOG
		dolog("ATA", "Status register read: %02X %i.%i", *result, channel, ATA_activeDrive(channel));
#endif
		return 1; //OK!
		break;
	default: //Unsupported?
		break;
	}
	return 0; //Unsupported!
port3_read: //Special port #3?
	port -= getControlPORTaddress(channel); //Get the port from the base!
	if (!ATA_Drives[channel][ATA_activeDrive(channel)]) //Invalid drive?
	{
		*result = 0; //Give 0: we're not present!
		return 1; //OK!
	}
	switch (port) //What port?
	{
	case 0: //Alternate status register?
		ATA_updateStatus(channel); //Update the status register if needed!
		*result = ATA[channel].Drive[ATA_activeDrive(channel)].STATUSREGISTER; //Get status!
#ifdef ATA_LOG
		dolog("ATA", "Alternate status register read: %02X %i.%i", *result, channel, ATA_activeDrive(channel));
#endif
		return 1; //OK!
		break;
	case 1: //Drive address register?
		*result = (ATA[channel].DriveAddressRegister&0x7F); //Give the data, make sure we don't apply the flag shared with the Floppy Disk Controller!
#ifdef ATA_LOG
		dolog("ATA", "Drive address register read: %02X %i.%i", *result, channel, ATA_activeDrive(channel));
#endif
		return 1; //OK!
		break;
	default: //Unsupported!
		break;
	}
	return 0; //Unsupported!
}

void resetPCISpaceIDE()
{
	//Info from: http://wiki.osdev.org/PCI
	PCI_IDE.DeviceID = 1;
	PCI_IDE.VendorID = 1; //DEVICEID::VENDORID: We're a ATA device!
	PCI_IDE.ProgIF = 0x80; //We use our own set interrupts and we're a parallel ATA controller!
	PCI_IDE.ClassCode = 1; //We...
	PCI_IDE.Subclass = 1; //Are an IDE controller
}

void ATA_ConfigurationSpaceChanged(uint_32 address, byte size)
{
	byte *addr;
	if (address == 0x3C) //IRQ changed?
	{
		PCI_IDE.InterruptLine = 0xFF; //We're unused, so let the software detect it, if required!
	}
	else //Might be unknown data?
	{
		addr = (((byte *)&PCI_IDE)+address); //Actual update location?
		if ((addr<(byte *)&PCI_IDE.BAR[0]) || (addr>((byte *)&PCI_IDE.BAR[3]+sizeof(PCI_IDE.BAR[3])))) //Unsupported update to unsupported location?
		{
			memset(addr,0,1); //Clear the set data!
		}
	}
	resetPCISpaceIDE(); //For read-only fields!
}

byte CDROM_DiskChanged = 0;

void ATA_DiskChanged(int disk)
{
	byte disk_ATA, disk_channel, disk_nr;
	switch (disk) //What disk?
	{
	//Four disk numbers!
	case HDD0:
		disk_nr = 0;
		break;
	case HDD1:
		disk_nr = 1;
		break;
	case CDROM0:
		disk_nr = 2;
		break;
	case CDROM1:
		disk_nr = 3;
		break;
	default: //Unsupported?
		return; //Abort!
	}
	disk_channel = ATA_DrivesReverse[disk_nr][0]; //The channel of the disk!
	disk_ATA = ATA_DrivesReverse[disk_nr][1]; //The master/slave of the disk!
	if ((disk_nr >= 2) && CDROM_DiskChanged) //CDROM changed?
	{
		ATA_ERRORREGISTER_MEDIACHANGEDW(disk_channel,disk_ATA,1); //We've changed media!
	}
	byte IS_CDROM = ((disk==CDROM0)||(disk==CDROM1)); //CD-ROM drive?
	if ((disk_channel == 0xFF) || (disk_ATA == 0xFF)) return; //Not mounted!
	uint_64 disk_size;
	switch (disk)
	{
	case HDD0: //HDD0 changed?
	case HDD1: //HDD1 changed?
	case CDROM0: //CDROM0 changed?
	case CDROM1: //CDROM1 changed?
		if (is_mounted(disk)) //Do we even have this drive?
		{
			disk_size = disksize(disk); //Get the disk's size!
			disk_size >>= 9; //Get the disk size in sectors!
			if ((disk ==HDD0) || (disk==HDD1)) ATA[disk_channel].Drive[disk_ATA].driveparams[0] = (1<<6)|(1<<10)|(1<<1); //Hard sectored, Fixed drive! Disk transfer rate>10MBs, hard-sectored.
			ATA[disk_channel].Drive[disk_ATA].driveparams[1] = ATA[disk_channel].Drive[disk_ATA].driveparams[54] = get_cylinders(disk_size); //1=Number of cylinders
			ATA[disk_channel].Drive[disk_ATA].driveparams[3] = ATA[disk_channel].Drive[disk_ATA].driveparams[55] = get_heads(disk_size); //3=Number of heads
			ATA[disk_channel].Drive[disk_ATA].driveparams[6] = ATA[disk_channel].Drive[disk_ATA].driveparams[56] = get_SPT(disk_size); //6=Sectors per track
			ATA[disk_channel].Drive[disk_ATA].driveparams[5] = IS_CDROM?0:0x200; //512 bytes per sector!
			ATA[disk_channel].Drive[disk_ATA].driveparams[4] = 0x200*(ATA[disk_channel].Drive[disk_ATA].driveparams[6]); //512 bytes per sector per track!
			ATA[disk_channel].Drive[disk_ATA].driveparams[20] = IS_CDROM?0:1; //Only single port I/O (no simultaneous transfers) on HDD only(ATA-1)!
			ATA[disk_channel].Drive[disk_ATA].driveparams[21] = 0x80; //Buffer size in sectors! We're a 64KB buffer, so 0x80 sectors buffered(of 512 bytes each)!

			ATA[disk_channel].Drive[disk_ATA].driveparams[49] = (1<<9); //LBA supported(bit 9), DMA unsupported(bit 8)!
			ATA[disk_channel].Drive[disk_ATA].driveparams[51] = 0x200; //PIO data transfer timing node(high 8 bits)!
			--disk_size; //LBA is 0-based, not 1 based!
			ATA[disk_channel].Drive[disk_ATA].driveparams[60] = (word)(disk_size & 0xFFFF); //Number of addressable LBA sectors, low word!
			ATA[disk_channel].Drive[disk_ATA].driveparams[61] = (word)(disk_size >> 16); //Number of addressable LBA sectors, high word!
			//ATA-1 supports up to word 63 only. Above is filled on ATAPI only(newer ATA versions)!
			ATA[disk_channel].Drive[disk_ATA].driveparams[72] = 0; //Major version! We're ATA/ATAPI 4 on CD-ROM, ATA-1 on HDD!
			ATA[disk_channel].Drive[disk_ATA].driveparams[72] = 0; //Minor version! We're ATA/ATAPI 4!
			ATA[disk_channel].Drive[disk_ATA].driveparams[80] = IS_CDROM?(1<<4):0x00; //Supports ATA-1 on HDD, ATA-4 on CD-ROM!
			ATA[disk_channel].Drive[disk_ATA].driveparams[81] = IS_CDROM?0x0017:0x0000; //ATA/ATAPI-4 T13 1153D revision 17 on CD-ROM, ATA (ATA-1) X3T9.2 781D prior to revision 4 for hard disk(=1, but 0 due to ATA-1 specification not mentioning it).
			ATA[disk_channel].Drive[disk_ATA].driveparams[82] = IS_CDROM?((1<<4)|(1<<9)|(1<<14)):0x0000; //On CD-ROM, PACKET; DEVICE RESET; NOP is supported, ON hard disk, only NOP is supported.
			ATA_updateCapacity(disk_channel,disk_ATA); //Update the drive capacity!
		}
		else //Drive not inserted?
		{
			memset(ATA[disk_channel].Drive[disk_ATA].driveparams, 0, sizeof(ATA[disk_channel].Drive[disk_ATA].driveparams)); //Clear the information on the drive: it's non-existant!
		}
		if ((disk == CDROM0) || (disk == CDROM1)) //CDROM?
		{
			ATA[disk_channel].Drive[disk_ATA].driveparams[0] = ((2 << 14) /*ATAPI DEVICE*/ | (5 << 8) /* Command packet set used by device */ | (1 << 7) /* Removable media device */ | (2 << 5) /* DRQ within 50us of receiving PACKET command */ | (0 << 0) /* 12-byte command packet */ ); //CDROM drive ID!
		}
		break;
	default: //Unknown?
		break;
	}
}

void initATA()
{
	memset(&ATA, 0, sizeof(ATA)); //Initialise our data!
	memset(&IRQtimer, 0, sizeof(IRQtimer)); //Init timers!
	//We don't register a disk change handler, because ATA doesn't change disks when running!
	//8-bits ports!
	register_PORTIN(&inATA8);
	register_PORTOUT(&outATA8);
	//16-bits port!
	register_PORTINW(&inATA16);
	register_PORTOUTW(&outATA16);

	//We don't implement DMA: this is done by our own DMA controller!
	//First, detect HDDs!
	memset(ATA_Drives, 0, sizeof(ATA_Drives)); //Init drives to unused!
	memset(ATA_DrivesReverse, 0, sizeof(ATA_DrivesReverse)); //Init reverse drives to unused!
	byte CDROM_channel = 1; //CDROM is the second channel by default!
	if (is_mounted(HDD0)) //Have HDD0?
	{
		ATA_Drives[0][0] = HDD0; //Mount HDD0!
		if (is_mounted(HDD1)) //Have HDD1?
		{
			ATA_Drives[0][1] = HDD1; //Mount HDD1!
		}
	}
	else if (is_mounted(HDD1)) //Have HDD1?
	{
		ATA_Drives[0][0] = HDD1; //Mount HDD1!
	}
	else
	{
		CDROM_channel = 0; //Move CDROM to primary channel!
	}
	ATA_Drives[CDROM_channel][0] = CDROM0; //CDROM0 always present as master!
	ATA_Drives[CDROM_channel][1] = CDROM1; //CDROM1 always present as slave!
	int i,j,k;
	int disk_reverse[4] = { HDD0,HDD1,CDROM0,CDROM1 }; //Our reverse lookup information values!
	for (i = 0;i < 4;i++) //Check all drives mounted!
	{
		ATA_DrivesReverse[i][0] = 0xFF; //Unassigned!
		ATA_DrivesReverse[i][1] = 0xFF; //Unassigned!
		for (j = 0;j < 2;j++)
		{
			for (k = 0;k < 2;k++)
			{
				if (ATA_Drives[j][k] == disk_reverse[i]) //Found?
				{
					if ((disk_reverse[i] == HDD0) || (disk_reverse[i] == HDD1))
					{
						ATA[j].Drive[k].preventMediumRemoval = 1; //We're preventing medium removal, when running the emulation!
					}
					ATA_DrivesReverse[i][0] = j;
					ATA_DrivesReverse[i][1] = k; //Load reverse lookup!
				}
			}
		}
	}
	//Now, apply the basic disk information (disk change/initialisation of parameters)!
	register_DISKCHANGE(HDD0, &ATA_DiskChanged);
	register_DISKCHANGE(HDD1, &ATA_DiskChanged);
	register_DISKCHANGE(CDROM0, &ATA_DiskChanged);
	register_DISKCHANGE(CDROM1, &ATA_DiskChanged);
	CDROM_DiskChanged = 0; //Init!
	ATA_DiskChanged(HDD0); //Init HDD0!
	ATA_DiskChanged(HDD1); //Init HDD1!
	ATA_DiskChanged(CDROM0); //Init HDD0!
	ATA_DiskChanged(CDROM1); //Init HDD1!
	CDROM_DiskChanged = 1; //We're changing when updating!
	memset(&PCI_IDE, 0, sizeof(PCI_IDE)); //Initialise to 0!
	register_PCI(&PCI_IDE, sizeof(PCI_IDE),&ATA_ConfigurationSpaceChanged); //Register the PCI data area!
	//Initialise our data area!
	resetPCISpaceIDE();
	ATA[0].resetTiming = 0.0; //Clear the reset timing!
	ATA[1].resetTiming = 0.0; //Clear the reset timing!
}
