/*

src:http://wiki.osdev.org/Programmable_Interval_Timer#Channel_2
82C54 PIT (Timer) (82C54(8253/8254 in older systems))

*/

#include "headers/types.h"
#include "headers/hardware/ports.h" //IO Port support!
#include "headers/hardware/pic.h" //irq support!
#include "headers/emu/sound.h" //PC speaker support for the current emu!
#include "headers/emu/timers.h" //Timer support!
#include "headers/hardware/8253.h" //Our own typedefs etc.

#include "headers/hardware/pcspeaker.h" //PC speaker support!
#include "headers/support/highrestimer.h" //High resolution timer support for current value!
#include "headers/support/locks.h" //Locking support!

//Are we disabled?
#define __HW_DISABLED 0

double timerfreq; //Done externally!

TicksHolder timerticks[3];
float timertime[3] = { 1000000000.0f / 18.2f,0.0f,0.0f }; //How much time does it take to expire (default to 0=18.2Hz timer)?
float currenttime[3] = { 0.0f,0.0f,0.0f }; //Current time passed!

extern byte EMU_RUNNING; //Emulator running? 0=Not running, 1=Running, Active CPU, 2=Running, Inactive CPU (BIOS etc.)

void cleanPIT0()
{
	getuspassed(&timerticks[0]); //Discard the time passed to the counter!
	getuspassed(&timerticks[1]); //Discard the time passed to the counter!
	getuspassed(&timerticks[2]); //Discard the time passed to the counter!
}

void updatePIT0() //Timer tick Irq
{
	byte channel;
	if (EMU_RUNNING==1) //Are we running?
	{
		for (channel = 0;channel < 3;channel++) //process all channels![
		{
			currenttime[channel] += (float)getnspassed(&timerticks[channel]); //Add the time passed to the counter!
			if ((currenttime[channel] >= timertime[channel]) && timertime[channel]) //Are we to trigger an interrupt?
			{
				currenttime[channel] -= timertime[channel]; //Rest!
				if (!channel) doirq(0); //PIT0 executes an IRQ on timeout!
			}
		}
	}
}

uint_32 pitcurrentlatch[3], pitlatch[3], pitcommand[3], pitdivisor[3];

//PC Speaker functionality in PIT

uint_32 PCSpeakerFrequency=0x10000; //PC Speaker Frequency from the PIT!
byte PCSpeakerPort; //Port 0x61 for the PC Speaker!
byte PCSpeakerIsRunning; //Speaker is running?

void startOrUpdateSpeaker(float frequency) //Start or update the running frequency!
{
	if (__HW_DISABLED) return; //Abort!
	if (PCSpeakerIsRunning) //Already running: need to update the speaker?
	{
		//Update speaker frequency!
		setSpeakerFrequency(0,frequency);
	}
	else //Start the speaker at the given frequency!
	{
		//Start speaker with given frequency!
		PCSpeakerIsRunning = 1; //We're running!
		setSpeakerFrequency(0,frequency); //Set the frequency first!
		enableSpeaker(0); //Finally: enable the speaker!
	}
}

void stopSpeaker() //Stop the running speaker!
{
	if (__HW_DISABLED) return; //Abort!
	if (PCSpeakerIsRunning) //Running: able to stop?
	{
		//Stop the speaker!
		disableSpeaker(0); //Disable the speaker!
		PCSpeakerIsRunning = 0; //Not running anymore!
	}
}

void updatePCSpeakerFrequency() //PC Speaker frequency has been updated!
{
	if (__HW_DISABLED) return; //Abort!
	float frequency;
	frequency = (1193180.0f/ PCSpeakerFrequency); //Calculate the frequency (Hz)
	if ((PCSpeakerPort&0x3)==0x3) //Enabled?
	{
		//Now, do hardware stuff!
		startOrUpdateSpeaker(frequency); //Start or update the speaker!
	}
	else //Disabled?
	{
		//Now, do hardware stuff!
		stopSpeaker(); //Stop a speaker if running!
	}
}

void updatePCSpeaker() //PC Speaker register has been updated!
{
	if (__HW_DISABLED) return; //Abort!
	if ((PCSpeakerPort&0x3)==0x3) //Enabled?
	{
		//Enable PC speaker!
		updatePCSpeakerFrequency(); //Enable it!
	}
	else //Disabled?
	{
		//Disable PC speaker!
		updatePCSpeakerFrequency(); //Disable it!
	}
}

//NEW HANDLER
uint_64 calculatedpitstate[3]; //Calculate state by time and last time handled!

void updatePITState(byte channel)
{
	//Calculate the current PIT0 state by frequency and time passed!
	uint_64 timepassed;
	static const float tickduration = (1.0f / 1193180.0f)*1000000000.0f; //How long does it take to process one tick in ns?
	timepassed = getnspassed_k(&timerticks[channel]); //How many time has passed since the last full state?
	calculatedpitstate[channel] = pitdivisor[channel]; //Load the current divisor (1-65536)
	if (calculatedpitstate[channel] == 65536) calculatedpitstate[channel] = 0; //We start counting from 0 instead of 65536!
	calculatedpitstate[channel] -= (uint_64)((float)timepassed / (float)tickduration); //Count down the current PIT0 state!
	calculatedpitstate[channel] &= 0xFFFF; //Convert it to 16-bits value of the PIT!
	pitlatch[channel] = calculatedpitstate[channel]; //Set the latch!
}

byte lastpit = 0;

byte in8253(word portnum, byte *result)
{
	byte pit;
	if (__HW_DISABLED) return 0; //Abort!
	switch (portnum)
	{
		case 0x40:
		case 0x41:
		case 0x42:
			pit = (byte)(portnum&0xFF);
			pit &= 3; //PIT!
			if (pitcommand[pit] & 0x30) //No latch mode?
			{
				updatePITState(pit); //Update the state: effect like a running timer!
			}
			switch (pitcommand[pit] & 0x30) //What input mode currently?
			{
			case 0x10: //Lo mode?
				*result = (pitlatch[pit] & 0xFF);
				break;
			case 0x20: //Hi mode?
				*result = ((pitlatch[pit]>>8) & 0xFF) ;
				break;
			case 0x00: //Latch mode?
			case 0x30: //Lo/hi mode?
				if (pitcurrentlatch[pit] == 0)
				{
					//Give the value!
					pitcurrentlatch[pit] = 1;
					*result = (pitlatch[pit] & 0xFF);
				}
				else
				{
					pitcurrentlatch[pit] = 0;
					*result = ((pitlatch[pit] >> 8) & 0xFF);
				}
				break;
			}
			return 1;
			break;
		case 0x43:
			*result = pitcommand[lastpit]; //Give the last command byte!
			return 1;
		case 0x61: //PC speaker? From original timer!
			*result = PCSpeakerPort; //Give the speaker port!
			return 1;
		default: //Unknown port?
			break; //Unknown port!
	}
	return 0; //Disabled!
}

byte out8253(word portnum, byte value)
{
	if (__HW_DISABLED) return 0; //Abort!
	byte old61; //For tracking updates!
	byte pit;
	switch (portnum)
	{
		case 0x40: //pit 0 data port
		case 0x41: //pit 1 data port
		case 0x42: //speaker data port
			pit = (byte)(portnum&0xFF);
			pit &= 3; //Low 2 bits only!
			switch (pitcommand[pit]&0x30) //What input mode currently?
			{
			case 0x10: //Lo mode?
				pitdivisor[pit] = (pitdivisor[pit] & 0xFF00) + (value & 0xFF);
				break;
			case 0x20: //Hi mode?
				pitdivisor[pit] = (pitdivisor[pit] & 0xFF) + ((value & 0xFF)<<8);
				break;
			case 0x00: //Latch mode?
			case 0x30: //Lo/hi mode?
				if (!pitcurrentlatch[pit])
				{
					pitdivisor[pit] = (pitdivisor[pit] & 0xFF00) + (value & 0xFF);
					pitcurrentlatch[pit] = 1;
				}
				else
				{
					pitdivisor[pit] = (pitdivisor[pit] & 0xFF) + ((value & 0xFF)<<8);
					pitcurrentlatch[pit] = 0;
				}
				break;
			}
			if (!pitdivisor[pit]) pitdivisor[pit] = 0x10000;
			initTicksHolder(&timerticks[pit]); //Initialise the timer ticks!
			timertime[pit] = SAFEDIV(1000000000.0f,SAFEDIV(1193180.0f, pitdivisor[pit])); //How much time do we take to expire?
			if (pit==2) //PC speaker?
			{
				PCSpeakerFrequency = pitdivisor[pit]; //The frequency of the PC speaker!
				updatePCSpeaker(); //Update the PC speaker!
			}
			return 1;
		case 0x43: //pit command port
			if ((value & 0xC0) == 0xC0) //Read-back command?
			{
				//TODO
			}
			else //Normal command?
			{
				byte channel;
				channel = (value >> 6);
				channel &= 3; //The channel!
				pitcommand[channel] = value; //Set the command for the port!
				switch (value&0x30) {
				case 0x00: //Latch count value?
					updatePITState(channel); //Update the state!
					break;
				case 0x10: //Mode lo only!
				case 0x20: //Mode hi only!
				case 0x30: //Mode lo/hi!
					break;
				}
				lastpit = channel; //The last channel effected!
				pitcurrentlatch[channel] = 0; //Reset the latch always!
			}
			return 1;
		//From above original:
	case 0x61: //PC Speaker?
		old61 = PCSpeakerPort; //Old value!
		PCSpeakerPort = (value&3); //Set the new port value, only low 2 bits are used!
		if (old61!=PCSpeakerPort) //Port changed?
		{
			updatePCSpeaker(); //The PC Speaker status has been updated!
		}
		return 1;
	default:
		break;
	}
	return 0; //Unhandled!
}

void init8253() {
	if (__HW_DISABLED) return; //Abort!
	register_PORTOUT(&out8253);
	register_PORTIN(&in8253);
}