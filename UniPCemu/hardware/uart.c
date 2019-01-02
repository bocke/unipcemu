//src: http://wiki.osdev.org/Serial_Ports

//UART chip emulation.

#include "headers/hardware/pic.h" //IRQ support!
#include "headers/hardware/uart.h" //UART support (ourselves)!
#include "headers/hardware/ports.h"  //Port support!

//Hardware disabled?
#define __HW_DISABLED 0

struct
{
	byte used; //Are we an used UART port?
	//+0 is data register (transmit or receive data)
	//+1 as well as +0 have alternative
	byte InterruptEnableRegister; //Either this register or Divisor Latch when 
	byte InterruptIdentificationRegister;
	byte FIFOControlRegister; //FIFO Control register!
	byte LineControlRegister;
	byte ModemControlRegister; //Bit0=DTR, 1=RTS, 2=Alternative output 1, 3=Alternative output 2, 4=Loopback mode, 5=Autoflow control (16750 only
	byte oldModemControlRegister; //Old modem control bits!
	byte LineStatusRegister; //Bit0=Data available, 1=Overrun error, 2=Parity error, 3=Framing error, 4=Break signal received, 5=THR is empty, 6=THR is empty and all bits are sent, 7=Errorneous data in FIFO.
	byte oldLineStatusRegister; //Old line status register to compare!
	byte activeModemStatus; //Bit0=CTS, 1=DSR, 2=Ring indicator, 3=Carrier detect
	byte ModemStatusRegister; //Bit4=CTS, 5=DSR, 6=Ring indicator, 7=Carrier detect; Bits 0-3=Bits 4-6 changes, reset when read.
	byte oldModemStatusRegister; //Last Modem status register values(high 4 bits)!
	byte ScratchRegister;
	//Seperate register alternative
	word DLAB; //The speed of transmission, 115200/DLAB=Speed set.
	byte TransmitterHoldingRegister; //Data to be written to the device!
	byte TransmitterShiftRegister; //Data we're transferring!
	byte DataHoldingRegister; //The data that's received (the buffer for the software to read when filled)! Aka Data Holding Register
	byte ReceiverBufferRegister; //The data that's being received.
	//This speed is the ammount of bits (data bits), stop bits (0=1, 1=1.5(with 5 bits data)/2(all other cases)) and parity bit when set, that are transferred per second.


	//The handlers for the device attached, if any!
	UART_setmodemcontrol setmodemcontrol;
	UART_getmodemstatus getmodemstatus;
	UART_receivedata receivedata;
	UART_senddata senddata;
	UART_hasdata hasdata;

	byte interrupt_causes[4]; //All possible causes of an interrupt!
	uint_32 receiveTiming; //UART receive timing!
	uint_32 sendTiming; //UART send timing!
	byte sendPhase; //What's happening on the sending side?
	byte receivePhase; //What's happening on the receiving side?
	uint_32 UART_bytetransfertiming; //UART byte received timing!
} UART_port[4]; //All UART ports!

//Value = 5+DataBits
#define UART_LINECONTROLREGISTER_DATABITSR(UART) (UART_port[UART].LineControlRegister&3)
//0=1, 1=1.5(DataBits=0) or 2(All other cases).
#define UART_LINECONTROLREGISTER_STOPBITSR(UART) ((UART_port[UART].LineControlRegister>>2)&1)
//Parity enabled?
#define UART_LINECONTROLREGISTER_PARITYENABLEDR(UART) ((UART_port[UART].LineControlRegister>>3)&1)
//0=Odd, 1=Even, 2=Mark, 3=Space.
#define UART_LINECONTROREGISTERL_PARITYTYPER(UART) ((UART_port[UART].LineControlRegister>>4)&3)
//Enable address 0&1 mapping to divisor?
#define UART_LINECONTROLREGISTER_DLABR(UART) ((UART_port[UART].LineControlRegister>>7)&1)

//Simple cause. 0=Modem Status Interrupt, 1=Transmitter Holding Register Empty Interrupt, 2=Received Data Available Interrrupt, 3=Receiver Line Status Interrupt!
#define UART_INTERRUPTCAUSE_SIMPLECAUSER(UART) ((UART_port[UART].InterruptIdentificationRegister>>1)&3)
#define UART_INTERRUPTCAUSE_SIMPLECAUSEW(UART,val) UART_port[UART].InterruptIdentificationRegister=((UART_port[UART].InterruptIdentificationRegister&(~6))|((val&3)<<1))

#define UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGR(UART) (UART_port[UART].InterruptIdentificationRegister&1)
#define UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGW(UART,val) UART_port[UART].InterruptIdentificationRegister=((UART_port[UART].InterruptIdentificationRegister&(~1))|(val&1))
#define UART_INTERRUPTIDENTIFICATIONREGISTER_TRANSMITTEREMPTYR(UART) ((UART_port[UART].InterruptIdentificationRegister>>1)&1)
#define UART_INTERRUPTIDENTIFICATIONREGISTER_TRANSMITTEREMPTYW(UART,val) UART_port[UART].InterruptIdentificationRegister=((UART_port[UART].InterruptIdentificationRegister&(~2))|((val&1)<<1))
#define UART_INTERRUPTIDENTIFICATIONREGISTER_BREADERRORR(UART) ((UART_port[UART].InterruptIdentificationRegister>>2)&1)
#define UART_INTERRUPTIDENTIFICATIONREGISTER_BREADERRORW(UART,val) UART_port[UART].InterruptIdentificationRegister=((UART_port[UART].InterruptIdentificationRegister&(~4))|((val&1)<<2))
#define UART_INTERRUPTIDENTIFICATIONREGISTER_STATUSCHANGER(UART) ((UART_port[UART].InterruptIdentificationRegister>>3)&1)
#define UART_INTERRUPTIDENTIFICATIONREGISTER_STATUSCHANGEW(UART,val) UART_port[UART].InterruptIdentificationRegister=((UART_port[UART].InterruptIdentificationRegister&(~8))|((val&1)<<3))
//0=No FIFO present, 1=Reserved, 2=FIFO Enabled, but not functioning, 3=FIFO Enabled.
#define UART_INTERRUPTIDENTIFICATIONREGISTER_ENABLE64BYTEFIFOR(UART) ((UART_port[UART].InterruptIdentificationRegister>>4)&1)
#define UART_INTERRUPTIDENTIFICATIONREGISTER_ENABLE64BYTEFIFOW(UART,val) UART_port[UART].InterruptIdentificationRegister=((UART_port[UART].InterruptIdentificationRegister&(~0x10))|((val&1)<<4))

//Full Interrupt Identification Register!

DOUBLE UART_clock = 0.0, UART_clocktick = 0.0; //The UART clock ticker!

void UART_handleInputs(); //Handle any input to the UART! Prototype!

byte allocatedUARTs;
byte allocUARTport()
{
	if (allocatedUARTs>=NUMITEMS(UART_port)) return 0xFF; //Port available?
	return allocatedUARTs++; //Get an ascending UART number!
}

OPTINLINE void launchUARTIRQ(byte COMport, byte cause) //Simple 2-bit cause.
{
	if (!UART_port[COMport].used) return; //Unused COM port!
	switch (cause) //What cause?
	{
	case 0: //Modem status changed?
		if (!(UART_port[COMport].InterruptEnableRegister & 8)) return; //Don't trigger if it's disabled!
		break;
	case 1: //Ready to send? (Transmitter Register Holder Register became empty)
		if (!(UART_port[COMport].InterruptEnableRegister & 2)) return; //Don't trigger if it's disabled!
		break;
	case 2: //Received data is available?
		if (!(UART_port[COMport].InterruptEnableRegister & 1)) return; //Don't trigger if it's disabled!
		break;
	case 3: //Receiver line status changed?
		if (!(UART_port[COMport].InterruptEnableRegister & 4)) return; //Don't trigger if it's disabled!
		break;
	default:
		break;
	}
	//Prepare our info!
	UART_port[COMport].interrupt_causes[cause & 3] = 1; //We're requesting an interrupt for this cause!

	//Finally launch the IRQ!
	if (COMport&1) //COM2&COM4?
	{
		raiseirq(3); //Do IRQ!
	}
	else //COM1&COM3?
	{
		raiseirq(4); //Do IRQ!
	}
}

void startUARTIRQ(byte IRQ)
{
	byte cause, port; //What cause are we?
	byte portbase, actualport;
	portbase = (IRQ == 4) ? 0 : 1; //Base port!
	for (port = 0;port < 2;port++) //List ports!
	{
		actualport = portbase + (port << 1); //Take the actual port!
		for (cause = 3;cause<4;--cause) //Check all causes, in order of priority!
		{
			if (UART_port[actualport].interrupt_causes[cause]) //We're is the cause?
			{
				UART_port[actualport].interrupt_causes[cause] = 0; //Reset the cause!
				UART_port[actualport].InterruptIdentificationRegister = 0; //Reset for our cause!
				UART_INTERRUPTCAUSE_SIMPLECAUSEW(actualport,(cause & 3)); //Load the simple cause (8250 way)!
				UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGW(actualport,0); //We've activated!
				return; //Stop scanning!
			}
		}
	}
}

byte getCOMport(word port) //What COM port?
{
	byte highnibble = (port>>8); //3 or 2
	byte lownibble = ((port>>3)&0x1F); //F or E
	
	byte result;
	result = 0; //Init COM port!
	switch (lownibble) //Get COM1/3?
	{
		case 0x1F: //COM1/2
			//Base 0
			break;
		case 0x1D: //COM3/4
			result |= 2; //Base 2 (port 3/4)
			break;
		default:
			result = 4; //Illegal!
			break;
	}

	switch (highnibble)
	{
		case 0x3: //Even COM port (COM1/2)
			break;
		case 0x2: //Odd COM port (COM3/4)
			result |= 1; //Add 1!
			break;
		default:
			result = 4; //Illegal!
			break;
	}
	
	return ((result<allocatedUARTs) && (result<4))?result:4; //Invalid by default!; //Give the COM port or 4 for unregistered COM port!
}

/*

Processed until http://en.wikibooks.org/wiki/Serial_Programming/8250_UART_Programming#Modem_Control_Register

*/

//Offset calculator!
#define COMPORT_offset(port) (port&0x7)

void updateUARTSpeed(byte COMport, word DLAB)
{
	uint_32 transfertime;
	transfertime = (7 + UART_LINECONTROLREGISTER_DATABITSR(COMport) + UART_LINECONTROLREGISTER_STOPBITSR(COMport)); //The total amount of bits that needs to be sent! Start, Data and Stop bits!
	//Every DLAB+1 / Line Control Register-dependant bytes per second! Simple formula instead of full emulation, like the PIT!
	//The UART is based on a 1.8432 clock, which is divided by 16 for the bit clock(start, data and stop bits).
	UART_port[COMport].UART_bytetransfertiming = ((uint_32)DLAB<<4) * transfertime; //Master clock divided by 16, divided by DLAB, divider by individual transfer time is the actual data rate!
}

byte PORT_readUART(word port, byte *result) //Read from the uart!
{
	byte COMport;
	if ((COMport = getCOMport(port))==4) //Unknown?
	{
		return 0; //Error: not our port!
	}
	switch (COMPORT_offset(port)) //What offset?
	{
		case 0: //Receiver buffer OR Low byte of Divisor Value?
			if (UART_LINECONTROLREGISTER_DLABR(COMport)) //DLAB?
			{
				*result = (UART_port[COMport].DLAB&0xFF); //Low byte!
			}
			else //Receiver buffer?
			{
				//Read from input buffer!
				if ((!UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGR(COMport)) && (UART_INTERRUPTCAUSE_SIMPLECAUSER(COMport)==2)) //We're to clear?
				{
					UART_port[COMport].InterruptIdentificationRegister = 0; //Reset the register!
					UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGW(COMport,1); //Reset interrupt pending!
					switch (COMport) //What port?
					{
					case 0:
					case 2:
						lowerirq(4); //Lower our IRQ if it's raised!
						acnowledgeIRQrequest(4); //Acnowledge!
						break;
					case 1:
					case 3:
						lowerirq(3); //Lower our IRQ if it's raised!
						acnowledgeIRQrequest(3); //Acnowledge!
						break;
					default:
						break;
					}
				}
				//return value with bits toggled by Line Control Register!
				*result = UART_port[COMport].DataHoldingRegister; //Receive the data, if any is available!
				if (UART_port[COMport].LineStatusRegister&0x01) //Buffer full?
				{
					UART_port[COMport].LineStatusRegister &= ~0x01; //We don't have any data anymore!
				}
			}
			break;
		case 1: //Interrupt Enable Register?
			if (UART_LINECONTROLREGISTER_DLABR(COMport)) //DLAB?
			{
				*result = ((UART_port[COMport].DLAB>>8)&0xFF); //High byte!
			}
			else //Interrupt enable register?
			{
				//bit0 = data available
				//bit1 = transmitter empty
				//bit2 = break/error
				//bit3 = status change
				*result = UART_port[COMport].InterruptEnableRegister; //Give the register!
			}
			break;
		case 2: //Interrupt ID registers?
			*result = UART_port[COMport].InterruptIdentificationRegister&(~0xE0); //Give the register! Indicate no FIFO!
			if ((!UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGR(COMport)) && (UART_INTERRUPTCAUSE_SIMPLECAUSER(COMport) == 1)) //We're to clear?
			{
				UART_port[COMport].InterruptIdentificationRegister = 0; //Reset the register!
				UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGW(COMport,1); //Reset interrupt pending!
				switch (COMport) //What port?
				{
				case 0:
				case 2:
					lowerirq(4); //Lower our IRQ if it's raised!
					acnowledgeIRQrequest(4); //Acnowledge!
					break;
				case 1:
				case 3:
					lowerirq(3); //Lower our IRQ if it's raised!
					acnowledgeIRQrequest(3); //Acnowledge!
					break;
				default:
					break;
				}
			}
			break;
		case 3: //Line Control Register?
			*result = UART_port[COMport].LineControlRegister; //Give the register!
			break;
		case 4:  //Modem Control Register?
			*result = UART_port[COMport].ModemControlRegister; //Give the register!
			break;
		case 5: //Line Status Register?
			if ((!UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGR(COMport)) && (UART_INTERRUPTCAUSE_SIMPLECAUSER(COMport) == 3)) //We're to clear?
			{
				UART_port[COMport].InterruptIdentificationRegister = 0; //Reset the register!
				UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGW(COMport,1); //Reset interrupt pending!
				switch (COMport) //What port?
				{
				case 0:
				case 2:
					lowerirq(4); //Lower our IRQ if it's raised!
					acnowledgeIRQrequest(4); //Acnowledge!
					break;
				case 1:
				case 3:
					lowerirq(3); //Lower our IRQ if it's raised!
					acnowledgeIRQrequest(3); //Acnowledge!
					break;
				default:
					break;
				}
			}
			*result = UART_port[COMport].LineStatusRegister; //Give the register!
			UART_port[COMport].LineStatusRegister &= ~0x1E; //Clear the register error flags!
			break;
		case 6: //Modem Status Register?
			if ((!UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGR(COMport)) && (UART_INTERRUPTCAUSE_SIMPLECAUSER(COMport) == 0)) //We're to clear?
			{
				UART_port[COMport].InterruptIdentificationRegister = 0; //Reset the register!
				UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGW(COMport,1); //Reset interrupt pending!
				switch (COMport) //What port?
				{
				case 0:
				case 2:
					lowerirq(4); //Lower our IRQ if it's raised!
					acnowledgeIRQrequest(4); //Acnowledge!
					break;
				case 1:
				case 3:
					lowerirq(3); //Lower our IRQ if it's raised!
					acnowledgeIRQrequest(3); //Acnowledge!
					break;
				default:
					break;
				}
			}

			*result = UART_port[COMport].ModemStatusRegister; //Give the register!
			UART_port[COMport].ModemStatusRegister &= 0xF0; //Only keep the relevant bits! The change bits are cleared!
			break;
		case 7: //Scratch register?
			//*result = UART_port[COMport].ScratchRegister; //Give the register!
			//Scratch register doesn't exist on a 8250!
			//break; //We do nothing yet!
		default:
			return 0; //Unknown port!
	}
	return 1; //Defined port!
}

byte PORT_writeUART(word port, byte value)
{
	byte COMport;
	if ((COMport = getCOMport(port))==4) //Unknown?
	{
		return 0; //Error!
	}
	switch (COMPORT_offset(port)) //What offset?
	{
		case 0: //Output buffer OR Low byte of Divisor Value?
			if (UART_LINECONTROLREGISTER_DLABR(COMport)) //DLAB?
			{
				UART_port[COMport].DLAB &= ~0xFF; //Clear the low byte!
				UART_port[COMport].DLAB |= value; //Low byte!
				updateUARTSpeed(COMport,UART_port[COMport].DLAB); //We're updated!
			}
			else //Output buffer?
			{
				if ((!UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGR(COMport)) && (UART_INTERRUPTCAUSE_SIMPLECAUSER(COMport) == 1)) //We're to clear?
				{
					UART_port[COMport].InterruptIdentificationRegister = 0; //Reset the register!
					UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGW(COMport,1); //Reset interrupt pending!
					switch (COMport) //What port?
					{
					case 0:
					case 2:
						lowerirq(4); //Lower our IRQ if it's raised!
						acnowledgeIRQrequest(4); //Acnowledge!
						break;
					case 1:
					case 3:
						lowerirq(3); //Lower our IRQ if it's raised!
						acnowledgeIRQrequest(3); //Acnowledge!
						break;
					default:
						break;
					}
				}

				if (UART_port[COMport].ModemControlRegister & 0x10) //In loopback mode? Reroute the Modem Control Register to Modem Status Register and act accordingly!
				{
					UART_port[COMport].DataHoldingRegister = value; //We've received this data!
					UART_port[COMport].LineStatusRegister |= 0x01; //We've received data!
					UART_handleInputs(); //Handle any inputs on the UART!
				}
				else //Not in loopback mode?
				{
					//Write to output buffer, toggling bits by Line Control Register!
					UART_port[COMport].TransmitterHoldingRegister = value;
					UART_port[COMport].LineStatusRegister &= ~0x60; //We're full, ready to transmit!
				}
			}
			break;
		case 1: //Interrupt Enable Register?
			if (UART_LINECONTROLREGISTER_DLABR(COMport)) //DLAB?
			{
				UART_port[COMport].DLAB &= ~0xFF00; //Clear the high byte!
				UART_port[COMport].DLAB |= (value<<8); //High!
				updateUARTSpeed(COMport, UART_port[COMport].DLAB); //We're updated!
			}
			else //Interrupt enable register?
			{
				//bit0 = data available
				//bit1 = transmitter empty
				//bit2 = break/error
				//bit3 = status change
				UART_port[COMport].InterruptEnableRegister = (value & 0xF); //Set the register! Clear the undefined bits, as per the documentation!
			}
			break;
		case 2: //FIFO control register?
			UART_port[COMport].FIFOControlRegister = value; //Set the register! Prevent bits from being set to indicate we don't have a FIFO!
			//Not used in the original 8250 UART.
			break;
		case 3: //Line Control Register?
			UART_port[COMport].LineControlRegister = value; //Set the register!
			break;
		case 4:  //Modem Control Register?
			UART_port[COMport].ModemControlRegister = (value&0x1F); //Set the register!
			//Handle anything concerning this?
			if (UART_port[COMport].setmodemcontrol) //Line handler added?
			{
				UART_port[COMport].setmodemcontrol(value&0xF); //Update the output lines!
			}
			if (((UART_port[COMport].ModemControlRegister^UART_port[COMport].oldModemControlRegister)&UART_port[COMport].ModemControlRegister) & 0x10) //Loopback mode enabled?
			{
				UART_handleInputs(); //Update the loopback status as required by updating the status register!
			}
			UART_port[COMport].oldModemControlRegister = UART_port[COMport].ModemControlRegister; //Save the old value for reference!
			break;
		case 7: //Scratch register?
			//UART_port[COMport].ScratchRegister = value; //Set the register!
			//Scratch register doesn't exist on a 8250!
			//break; //We do nothing yet!
		default: //Unknown write register?
			return 0;
			break;
	}
	return 1; //We're supported!
}

void UART_handleInputs() //Handle any input to the UART!
{
	int i;
	byte modemstatusinterrupt, checknewmodemstatus;

	//Raise the IRQ for the first device to give input!
	for (i = 0;i < 4;i++) //Process all ports!
	{
		//Read the Modem Status, update bits, check for interrupts!
		modemstatusinterrupt = 0; //Last status!
		if (UART_port[i].getmodemstatus && ((UART_port[i].ModemControlRegister&0x10)==0)) //Modem status available and not in Loopback mode?
		{
			UART_port[i].activeModemStatus = UART_port[i].getmodemstatus(); //Retrieve the modem status from the peripheral!

			//Update the modem status register accordingly!
			SETBITS(UART_port[i].ModemStatusRegister,4,0xF,UART_port[i].activeModemStatus); //Set the high bits of the modem status to our input lines!
			checknewmodemstatus = 1; //Check the new status!
		}
		else if (UART_port[i].ModemControlRegister & 0x10) //In loopback mode? Reroute the Modem Control Register to Modem Status Register and act accordingly!
		{
			//Update the modem status register accordingly!
			SETBITS(UART_port[i].ModemStatusRegister, 4, 0xF, UART_port[i].ModemControlRegister&0xF); //Set the high bits of the modem status to our input lines!
			checknewmodemstatus = 1; //Check the new status!
		}
		else //No status to report?
		{
			checknewmodemstatus = 0; //Check the new status!
		}
		if (likely(checknewmodemstatus)) //Are we to verify the new modem status?
		{
			//First, check for interrupts to be triggered!
			modemstatusinterrupt |= (((UART_port[i].ModemStatusRegister^UART_port[i].oldModemStatusRegister) >> 4) & 0xB); //Bits have changed set bits 0,1,3? Ring has other indicators!
			modemstatusinterrupt |= (((UART_port[i].oldModemStatusRegister)&(~UART_port[i].ModemStatusRegister)) >> 4) & 0x4; //Only set the Ring lowered bit when the ring indicator is lowered!
			//Report the new delta status to the register and update it with it's new status, where not set yet.
			UART_port[i].ModemStatusRegister |= (((UART_port[i].ModemStatusRegister^UART_port[i].oldModemStatusRegister) >> 4) & 0xB); //Bits have changed set bits 0,1,3? Ring has other indicators!
			UART_port[i].ModemStatusRegister |= (((UART_port[i].oldModemStatusRegister&(~UART_port[i].ModemStatusRegister)) >> 4) & 0x4); //Only set the Ring lowered bit when the ring indicator is lowered!
			UART_port[i].oldModemStatusRegister = UART_port[i].ModemStatusRegister; //Update the old modem status register!
		}
		if (unlikely((((UART_port[i].oldLineStatusRegister^UART_port[i].LineStatusRegister)&UART_port[i].LineStatusRegister) & 0x1E) || (UART_port[i].interrupt_causes[3]))) //Line status has raised an error or required to be raised?
		{
			launchUARTIRQ(i, 3); //We're changing the Line Status Register!
		}
		if (unlikely((((UART_port[i].oldLineStatusRegister^UART_port[i].LineStatusRegister)&UART_port[i].LineStatusRegister) & 0x01) || (UART_port[i].interrupt_causes[2]))) //Have we received data or required to be raised?
		{
			launchUARTIRQ(i, 2); //We've received data!
		}
		if (unlikely((((UART_port[i].oldLineStatusRegister^UART_port[i].LineStatusRegister)&UART_port[i].LineStatusRegister) & 0x20) || (UART_port[i].interrupt_causes[1]))) //Sent a byte of data(full transmitter holder register becomes empty)?
		{
			launchUARTIRQ(i, 1); //We've sent data!
		}
		if (unlikely((modemstatusinterrupt) || (UART_port[i].interrupt_causes[0]))) //Status changed or required to be raised?
		{
			launchUARTIRQ(i, 0); //Modem status changed!
		}
		UART_port[i].oldLineStatusRegister = UART_port[i].LineStatusRegister; //Save for difference checking!
	}
}

void updateUART(DOUBLE timepassed)
{
	byte UART; //Check all UARTs!
	uint_32 clockticks; //The clock ticks to process!
	uint_32 clocking;
	UART_clock += timepassed; //Tick our master clock!
	if (unlikely(UART_clock>=UART_clocktick)) //Ticking the UART clock?
	{
		clockticks = (uint_32)(UART_clock/UART_clocktick); //Divide the clock by the ticks to apply!
		UART_clock -= (DOUBLE)clockticks*UART_clocktick; //Rest the clocks!

		//Check all UART received data!
		for (UART=0;UART<4;++UART) //Check all UARTs!
		{
			clocking = clockticks; //How many ticks to tick!
			for (;clocking;--clocking) //Process all clocks!
			{
				//Tick receiver!
				switch (UART_port[UART].receivePhase) //What receive phase?
				{
					case 0: //Checking for start of transfer?
						if (unlikely(!(UART_port[UART].hasdata&&UART_port[UART].receivedata))) break; //Can't receive?
						if (unlikely(UART_port[UART].hasdata())) //Do we have data to receive and not prioritizing sending data?
						{
							if (likely((UART_port[UART].LineStatusRegister&0x01)==0)) //No data received yet?
							{
								UART_port[UART].ReceiverBufferRegister = UART_port[UART].receivedata(); //Read the data to receive!

								//Start transferring data...
								UART_port[UART].receiveTiming = UART_port[UART].UART_bytetransfertiming+1; //Duration of the transfer!
								UART_port[UART].receivePhase = 1; //Pending finish of transfer!
							}
							else break; //Can't receive!
						}
						else break; //Nothing to receive?
						//Finish transferring fallthrough!
					case 1: //Transferring data?
						if (--UART_port[UART].receiveTiming) break; //Busy transferring?
						UART_port[UART].receivePhase = 2; //Finish transferring!
					case 2: //Finish transfer!
						//Finished transferring data.
						if (UART_port[UART].ModemControlRegister & 0x10) break; //In loopback mode? Prevent any bytes from hardware from arriving until we aren't looping back anymore!
						if (UART_port[UART].LineStatusRegister & 0x01) //Receiver buffer filled? Overrun!
						{
							UART_port[UART].LineStatusRegister |= 0x2; //Signal overrun! Receive the byte as normally, overwriting what's there!
						}
						UART_port[UART].DataHoldingRegister = UART_port[UART].ReceiverBufferRegister; //We've received this data!
						UART_port[UART].LineStatusRegister |= 0x01; //We've received data!
						UART_port[UART].receivePhase = 0; //Start polling again!
						break;
				}

				switch (UART_port[UART].sendPhase) //What receive phase?
				{
					case 0: //Checking for start of transfer?
						if (unlikely(UART_port[UART].senddata && ((UART_port[UART].LineStatusRegister & 0x20) == 0))) //Something to transfer?
						{
							//Start transferring data...
							UART_port[UART].LineStatusRegister |= 0x20; //The Transmitter Holding Register is empty!
							UART_port[UART].TransmitterShiftRegister = UART_port[UART].TransmitterHoldingRegister; //Move to shift register!
							UART_port[UART].sendTiming = UART_port[UART].UART_bytetransfertiming+1; //Duration of the transfer!
							UART_port[UART].sendPhase = 1; //Pending finish of transfer!
						}
						else break; //Nothing to send!
						//Finish transferring fallthrough!
					case 1: //Transferring data?
						if (--UART_port[UART].sendTiming) break; //Busy transferring?
						UART_port[UART].sendPhase = 2; //Finish transferring!
					case 2: //Finish transfer!
						//Finished transferring data.
						UART_port[UART].senddata(UART_port[UART].TransmitterShiftRegister); //Send the data!

						//Data is sent, so update status when finished!
						if ((UART_port[UART].LineStatusRegister&0x20)==0x20) //Transmitter Shift emptied to peripheral and Holding Register is still empty?
						{
							UART_port[UART].LineStatusRegister |= 0x40; //The Transmitter Holding Register and Shift Register are both empty!
						}
						UART_port[UART].sendPhase = 0; //Start polling again!
						break;
				}
			}
		}

		UART_handleInputs(); //Handle the input received, when needed, as well as other conditions required!
	}
}

void UART_registerdevice(byte portnumber, UART_setmodemcontrol setmodemcontrol, UART_getmodemstatus getmodemstatus, UART_hasdata hasdata, UART_receivedata receivedata, UART_senddata senddata)
{
	if (portnumber > 3) return; //Invalid port!
	//Register the handlers!
	UART_port[portnumber].used = 1; //We're an used UART port!
	UART_port[portnumber].setmodemcontrol = setmodemcontrol;
	UART_port[portnumber].hasdata = hasdata;
	UART_port[portnumber].receivedata = receivedata;
	UART_port[portnumber].senddata = senddata;
	UART_port[portnumber].getmodemstatus = getmodemstatus;
}

void initUART() //Init software debugger!
{
	if (__HW_DISABLED) return; //Abort!
	memset(&UART_port,0,sizeof(UART_port)); //Clear memory used!
	register_PORTOUT(&PORT_writeUART);
	register_PORTIN(&PORT_readUART);
	registerIRQ(3, &startUARTIRQ, NULL); //Register our IRQ finish!
	registerIRQ(4, &startUARTIRQ, NULL); //Register our IRQ finish!
	int i;
	for (i = 0;i < 4;i++)
	{
		UART_INTERRUPTIDENTIFICATIONREGISTER_INTERRUPTPENDINGW(i >> 4,1); //We're not executing!
		UART_port[i].LineStatusRegister = 0x60; //Receiver buffer not ready for reading, Transmitter Holding register and Shift register are empty.
	}
	UART_clock = 0.0; //Init our clock!
	#ifdef IS_LONGDOUBLE
	UART_clocktick = 1000000000.0L/1843200.0L; //The clock of the UART ticking!
	#else
	UART_clocktick = 1000000000.0/1843200.0; //The clock of the UART ticking!
	#endif
	allocatedUARTs = 0; //Initialize the allocated UART number!
}
