#include "headers/types.h" //Basic type support!
#include "headers/hardware/pic.h" //PIC!
#include "headers/emu/timers.h" //Timing!
#include "headers/support/log.h" //Logging support!
#include "headers/bios/bios.h" //BIOS support!
#include "headers/support/locks.h" //Locking support!
#include "headers/hardware/ports.h" //Port support!
#include "headers/support/highrestimer.h" //Time support!
#include "headers/emu/debugger/debugger.h" //Debugger POST code used support!

//For time support!
#ifdef IS_PSP
#include <psprtc.h> //PSP Real Time Clock atm!
#endif

#include <time.h>

//Biggest Signed Integer value available!
#define BIGGESTSINT int_64

/*

CMOS&RTC (Combined!)

*/

//Are we disabled?
#define __HW_DISABLED 0

#define DIVIDERCHAIN_DISABLED 0
#define DIVIDERCHAIN_ENABLED 1
#define DIVIDERCHAIN_TEST 2
#define DIVIDERCHAIN_RESET 3

byte dcc = DIVIDERCHAIN_DISABLED; //Current divider chain!

byte XTMode = 0;

CMOS_Type CMOS;

extern byte NMI; //NMI interrupt enabled?

extern BIOS_Settings_TYPE BIOS_Settings; //The BIOS settings loaded!
extern byte is_Compaq; //Are we emulating a Compaq device?
extern byte is_XT; //Are we emulating a XT device?
extern byte is_PS2; //Are we emulating PS2 extensions?

#define FLOPPY_NONE 0
#define FLOPPY_360 1
#define FLOPPY_12 2
#define FLOPPY_720 3
#define FLOPPY_144 4
#define FLOPPY_288 5

OPTINLINE word decodeBCD(word bcd)
{
	INLINEREGISTER word temp, result=0;
	temp = bcd; //Load the BCD value!
	result += (temp&0xF); //Factor 1!
	temp >>= 4;
	result += (temp&0xF)*10; //Factor 10!
	temp >>= 4;
	result += (temp&0xF)*100; //Factor 100!
	temp >>= 4;
	result += (temp&0xF)*1000; //Factor 1000!
	return result; //Give the decoded integer value!
}

OPTINLINE word encodeBCD(word value)
{
	INLINEREGISTER word temp,result=0;
	temp = value; //Load the original value!
	temp %= 10000; //Wrap around!
	result |= (0x1000*(temp/1000)); //Factor 1000!
	temp %= 1000;
	result |= (0x0100*(temp/100)); //Factor 100
	temp %= 100;
	result |= (0x0010*(temp/10)); //Factor 10!
	temp %= 10;
	result |= temp; //Factor 1!
	return result;
}

OPTINLINE byte encodeBCD8(byte value, byte is12hour)
{
	if ((CMOS.DATA.DATA80.info.STATUSREGISTERB&SRB_DATAMODEBINARY)==0) //BCD mode?
	{
		if (is12hour) //12-hour format?
		{
			return ((encodeBCD(value&0x7F)&0x7F)); //Encode it!
		}
		return (encodeBCD(value)&0xFF); //Encode it!
	}
	return value; //Binary mode!
}

OPTINLINE byte decodeBCD8(byte value, byte is12hour)
{
	if ((CMOS.DATA.DATA80.info.STATUSREGISTERB&SRB_DATAMODEBINARY)==0) //BCD mode?
	{
		if (is12hour) //12-hour format?
		{
			return ((decodeBCD(value&0x7F)&0x7F)); //Decode it!
		}
		return (decodeBCD(value)&0xFF); //Decode it!
	}
	return value; //Binary mode!
}

OPTINLINE void loadCMOSDefaults()
{
	memset(&CMOS.DATA,0,sizeof(CMOS.DATA)); //Clear/init CMOS!
	CMOS.DATA.timedivergeance = 0; //No second divergeance!
	CMOS.DATA.timedivergeance2 = 0; //No us divergeance!
	//We don't affect loaded: we're not loaded and invalid by default!
}

void RTC_raiseIRQ()
{
	raiseirq(8); //We're the cause of the interrupt!
}

void RTC_PeriodicInterrupt() //Periodic Interrupt!
{
	if (CMOS.DATA.DATA80.data[0xC]&0x70) return; //Disable when pending!
	CMOS.DATA.DATA80.data[0x0C] |= 0x40; //Periodic Interrupt flag is always set!
	RTC_raiseIRQ(); //Raise the IRQ!
}

void RTC_UpdateEndedInterrupt() //Update Ended Interrupt!
{
	if (CMOS.DATA.DATA80.data[0xC]&0x70) return; //Disable when pending!
	CMOS.DATA.DATA80.data[0x0C] |= 0x10; //Update Ended Interrupt flag!
	RTC_raiseIRQ(); //Raise the IRQ!
}

void RTC_AlarmInterrupt() //Alarm handler!
{
	if (CMOS.DATA.DATA80.data[0xC]&0x70) return; //Disable when pending!
	CMOS.DATA.DATA80.data[0x0C] |= 0x20; //Alarm Interrupt flag!
	RTC_raiseIRQ(); //Raise the IRQ!
}

OPTINLINE void updatedividerchain() //0-1=Disabled, 2=Normal operation, 3-5=TEST, 6-7=RESET
{
	switch ((CMOS.DATA.DATA80.data[0xA]>>4)&7) //Divider chain control(dcc in Bochs)!
	{
		case 0:
		case 1:
			dcc = DIVIDERCHAIN_DISABLED; //Disabled!
			break;
		case 2:
			dcc = DIVIDERCHAIN_ENABLED; //Enabled!
			break;
		case 3:
		case 4:
		case 5:
			dcc = DIVIDERCHAIN_TEST; //TEST
			break;
		case 6:
		case 7:
		default:
			dcc =  DIVIDERCHAIN_RESET; //RESET!
			break;
	}
}

OPTINLINE void RTC_Handler(byte lastsecond) //Handle RTC Timer Tick!
{
	uint_32 oldrate, bitstoggled=0; //Old output!
	oldrate = CMOS.currentRate; //Save the old output for comparision!
	++CMOS.currentRate; //Increase the input divider to the next stage(22-bit divider at 32kHz(32kHz ticks))!
	bitstoggled = CMOS.currentRate^oldrate; //What bits have been toggled!

	if (CMOS.DATA.DATA80.info.STATUSREGISTERB&SRB_ENABLEPERIODICINTERRUPT) //Enabled?
	{
		if (bitstoggled&(CMOS.RateDivider<<1)) //Overflow on Rate(divided by 2 for our rate, since it's square wave signal converted to Hz)?
		{
			RTC_PeriodicInterrupt(); //Handle!
		}
	}

	if (CMOS.DATA.DATA80.info.STATUSREGISTERB&SRB_ENABLESQUAREWAVEOUTPUT) //Square Wave generator enabled?
	{
		if (bitstoggled&CMOS.RateDivider) //Overflow on Rate? We're generating a square wave at the specified frequency!
		{
			CMOS.SquareWave ^= 1; //Toggle the square wave!
			//It's unknown what the Square Wave output is connected to, if it's connected at all?
		}
	}

	if ((CMOS.DATA.DATA80.info.STATUSREGISTERB&SRB_ENABLEUPDATEENDEDINTERRUPT) && ((CMOS.DATA.DATA80.info.STATUSREGISTERB&SRB_ENABLECYCLEUPDATE) == 0) && (dcc!=DIVIDERCHAIN_RESET)) //Enabled and updated?
	{
		if (CMOS.DATA.DATA80.info.RTC_Seconds != lastsecond) //We're updated at all?
		{
			RTC_UpdateEndedInterrupt(); //Handle!
		}
	}

	if (((CMOS.DATA.DATA80.info.RTC_Hours==CMOS.DATA.DATA80.info.RTC_HourAlarm) || ((CMOS.DATA.DATA80.info.RTC_HourAlarm&0xC0)==0xC0)) && //Hour set or ignored?
		((CMOS.DATA.DATA80.info.RTC_Minutes==CMOS.DATA.DATA80.info.RTC_MinuteAlarm) || ((CMOS.DATA.DATA80.info.RTC_MinuteAlarm & 0xC0) == 0xC0)) && //Minute set or ignored?
		((CMOS.DATA.DATA80.info.RTC_Seconds==CMOS.DATA.DATA80.info.RTC_SecondAlarm) || ((CMOS.DATA.DATA80.info.RTC_SecondAlarm & 0xC0) == 0xC0)) && //Second set or ignored?
		(CMOS.DATA.DATA80.info.RTC_Seconds!=lastsecond) && //Second changed and check for alarm?
		(CMOS.DATA.DATA80.info.STATUSREGISTERB&SRB_ENABLEALARMINTERRUPT)) //Alarm enabled?
	{
		RTC_AlarmInterrupt(); //Handle the alarm!
	}
}

//Our accurate time support:

typedef struct
{
	uint_64 year;
	byte month;
	byte day;
	byte hour;
	byte minute;
	byte second;
	byte s100; //100th seconds(use either this or microseconds, since they both give the same time, only this one is rounded down!)
	byte s10000; //10000th seconds!
	uint_64 us; //Microseconds?
	byte dst;
	byte weekday;
} accuratetime;

//Our accuratetime epoch support!

//Epoch time values for supported OS!
#define EPOCH_YR 1970
#define SECS_DAY (3600*24)
#define YEAR0 0
//Is this a leap year?
#define LEAPYEAR(year) ( (year % 4 == 0 && year % 100 != 0) || ( year % 400 == 0))
//What is the size of this year in days?
#define YEARSIZE(year) (LEAPYEAR(year)?366:365)

byte _ytab[2][12] = { //Days within months!
	{ 31,28,31,30,31,30,31,31,30,31,30,31 }, //Normal year
	{ 31,29,31,30,31,30,31,31,30,31,30,31 } //Leap year
};

OPTINLINE byte epochtoaccuratetime(UniversalTimeOfDay *curtime, accuratetime *datetime)
{
	//More accurate timing than default!
	datetime->us = curtime->tv_usec;
	datetime->s100 = (byte)(curtime->tv_usec/10000); //10000us=1/100 second!
	datetime->s10000 = (byte)((curtime->tv_usec%10000)/100); //100us=1/10000th second!

	//Further is directly taken from the http://stackoverflow.com/questions/1692184/converting-epoch-time-to-real-date-time gmtime source code.
	uint_64 dayclock, dayno;
	uint_32 year = EPOCH_YR;

	dayclock = (uint_64)curtime->tv_sec % SECS_DAY;
	dayno = (uint_64)curtime->tv_sec / SECS_DAY;

	datetime->second = dayclock % 60;
	datetime->minute = (byte)((dayclock % 3600) / 60);
	datetime->hour = (byte)(dayclock / 3600);
	datetime->weekday = (dayno + 4) % 7;       /* day 0 was a thursday */
	for (;dayno >= (unsigned long)YEARSIZE(year);)
	{
		dayno -= YEARSIZE(year);
		year++;
	}
	datetime->year = year - YEAR0;
	datetime->day = (byte)dayno;
	datetime->month = 0;
	while (dayno >= _ytab[LEAPYEAR(year)][datetime->month]) {
		dayno -= _ytab[LEAPYEAR(year)][datetime->month];
		++datetime->month;
	}
	++datetime->month; //We're one month further(months start at one, not zero)!
	datetime->day = (byte)(dayno + 1);
	datetime->dst = 0;

	return 1; //Always successfully converted!
}

//Sizes of minutes, hours and days in Epoch time units.
#define MINUTESIZE 60
#define HOURSIZE 3600
#define DAYSIZE (3600*24)

OPTINLINE byte accuratetimetoepoch(accuratetime *curtime, UniversalTimeOfDay *datetime)
{
	uint_64 seconds=0;
	if ((curtime->us-(curtime->us%100))!=(((curtime->s100)*10000)+(curtime->s10000*100))) return 0; //Invalid time to convert: 100th&10000th seconds doesn't match us(this is supposed to be the same!)
	if (curtime->year<1970) return 0; //Before 1970 isn't supported!
	datetime->tv_usec = (uint_32)curtime->us; //Save the microseconds directly!
	uint_64 year;
	byte counter;
	byte leapyear;
	for (year=curtime->year;year>1970;) //Process the years!
	{
		--year; //The previous year has passed!
		seconds += YEARSIZE(year)*DAYSIZE; //Add the year that has passed!
	}
	leapyear = LEAPYEAR(curtime->year); //Are we a leap year?
	//Now, only months etc. are left!
	for (counter = curtime->month;counter>1;) //Process the months!
	{
		seconds += _ytab[leapyear][11-(--counter)]*DAYSIZE; //Add a month that has passed!
	}
	//Now only days, hours, minutes and seconds are left!
	seconds += DAYSIZE*(curtime->day?(curtime->day-1):0); //Days start at 1!
	seconds += HOURSIZE*curtime->hour;
	seconds += MINUTESIZE*curtime->minute;
	seconds += curtime->second;

	datetime->tv_sec = (uint_64)seconds; //The amount of seconds!
	return 1; //Successfully converted!
}

OPTINLINE byte encodeBCDhour(byte hour)
{
	byte result;
	if ((CMOS.DATA.DATA80.info.STATUSREGISTERB&SRB_ENABLE24HOURMODE)==0) //Need translation to/from 12-hour mode?
	{
		if (hour==0) //Midnight is 12AM, Noon=12PM, otherwise AM or PM.
		{
			hour = 12; //Midnight!
			result = 0; //Midnight!
		}
		else if (hour==12) //Midnight is 12AM, Noon=12PM, otherwise AM or PM.
		{
			hour = 12; //Noon!
			result = 0x80; //Noon!
		}
		else if (hour<12) //1:00-11:59:59 hour?
		{
			result = 0x00; //Clear the PM bit!
			//Hour is taken directly!
		}
		else //13:00-23:59?
		{
			result = 0x80; //We're PM!
			hour -= 12; //Convert to PM hour!
		}
		return (encodeBCD8(hour,1)|result); //Give the correct BCD with PM bit!
	}
	return encodeBCD8(hour,0); //Unmodified!
}

OPTINLINE byte decodeBCDhour(byte hour)
{
	byte result;
	if ((CMOS.DATA.DATA80.info.STATUSREGISTERB&SRB_ENABLE24HOURMODE)==0) //Need translation to/from 12-hour mode?
	{
		result = (hour&0x80)?12:0; //PM vs AM!
		hour &= 0x7F; //Take the remaining values without our PM bit!
		hour = decodeBCD8(hour,1); //Decode the hour!
		if (result==12) //12AM/PM is a special case!
		{
			hour = 0; //We're Midnight/noon: convert it back!
		}
		return (result+hour); //12-hour half + hours = 24-hour hour!
	}
	return decodeBCD8(hour,0); //Unmodified!
}

//CMOS time encoding support!
OPTINLINE void CMOS_decodetime(accuratetime *curtime) //Decode time into the current time!
{
	curtime->year = decodeBCD8(CMOS.DATA.DATA80.info.RTC_Year,0); //The year to compare to!
	curtime->year += (CMOS.DATA.centuryisbinary?/*CMOS.DATA.DATA80.data[0x32]*/ 19:decodeBCD8(CMOS.DATA.DATA80.data[0x32],0))*100; //Add the century! This value is the current year divided by 100, wrapped around at 100 centuries!
	curtime->month = decodeBCD8(CMOS.DATA.DATA80.info.RTC_Month,0); //The month to compare to!
	curtime->day = decodeBCD8(CMOS.DATA.DATA80.info.RTC_DateOfMonth,0); //The day to compare to!
	curtime->hour = decodeBCDhour(CMOS.DATA.DATA80.info.RTC_Hours); //H
	curtime->minute = decodeBCD8(CMOS.DATA.DATA80.info.RTC_Minutes,0); //M
	curtime->second = decodeBCD8(CMOS.DATA.DATA80.info.RTC_Seconds,0); //S
	curtime->weekday = decodeBCD8(CMOS.DATA.DATA80.info.RTC_DayOfWeek,0); //Day of week!
	curtime->s100 = decodeBCD8(CMOS.DATA.s100,0); //The 100th seconds!
	curtime->s10000 = decodeBCD8(CMOS.DATA.s10000,0); //The 10000th seconds!
	curtime->us = (curtime->s100*10000)+(curtime->s10000*100); //The same as above, make sure we match!
}

OPTINLINE void CMOS_encodetime(accuratetime *curtime) //Encode time into the current time!
{
	if (CMOS.DATA.centuryisbinary==0) CMOS.DATA.DATA80.data[0x32] = encodeBCD8((curtime->year/100)%100,0); //Encode when possible!
	//else CMOS.DATA.DATA80.data[0x32] = ((curtime->year/100)&0xFF); //The century with safety wrapping!
	CMOS.DATA.DATA80.info.RTC_Year = encodeBCD8(curtime->year%100,0);
	CMOS.DATA.DATA80.info.RTC_Month = encodeBCD8(curtime->month,0);
	CMOS.DATA.DATA80.info.RTC_DateOfMonth = encodeBCD8(curtime->day,0);

	CMOS.DATA.DATA80.info.RTC_Hours = encodeBCDhour(curtime->hour); //Hour has 12-hour format support!
	CMOS.DATA.DATA80.info.RTC_Minutes = encodeBCD8(curtime->minute,0);
	CMOS.DATA.DATA80.info.RTC_Seconds = encodeBCD8(curtime->second,0);
	CMOS.DATA.DATA80.info.RTC_DayOfWeek = encodeBCD8(curtime->weekday,0); //The day of the week!
	CMOS.DATA.s100 = encodeBCD8(curtime->s100,0); //The 100th seconds!
	CMOS.DATA.s10000 = encodeBCD8(curtime->s10000,0); //The 10000th seconds!
}

//Divergeance support!
OPTINLINE byte calcDivergeance(accuratetime *time1, accuratetime *time2, int_64 *divergeance_sec, int_64 *divergeance_usec) //Calculates the difference of time1 compared to time2(reference time)!
{
	UniversalTimeOfDay time1val, time2val; //Our time values!
	if (accuratetimetoepoch(time1, &time1val)) //Converted to universal value?
	{
		if (accuratetimetoepoch(time2, &time2val)) //Converted to universal value?
		{
			BIGGESTSINT applyingtime; //Biggest integer value we have!
			applyingtime = (((((BIGGESTSINT)time1val.tv_sec * 1000000) + (BIGGESTSINT)time1val.tv_usec) - (((BIGGESTSINT)time2val.tv_sec * 1000000) + (BIGGESTSINT)time2val.tv_usec))); //Difference in usec!
			*divergeance_sec = applyingtime/1000000; //Seconds!
			*divergeance_usec = applyingtime%1000000; //Microseconds!
			return 1; //Give the difference time!
		}
	}
	return 0; //Unknown: Don't apply divergeance!
}

OPTINLINE byte applyDivergeance(accuratetime *curtime, int_64 divergeance_sec, int_64 divergeance_usec) //Apply divergeance to accurate time!
{
	UniversalTimeOfDay timeval; //The accurate time value!
	BIGGESTSINT applyingtime; //Biggest integer value we have!
	if (accuratetimetoepoch(curtime, &timeval)) //Converted to epoch?
	{
		applyingtime = (((BIGGESTSINT)timeval.tv_sec * 1000000) + (BIGGESTSINT)timeval.tv_usec); //Direct time conversion!
		applyingtime += ((BIGGESTSINT)divergeance_sec*1000000); //Add the divergeance: we're applying the destination time!
		applyingtime += (BIGGESTSINT)divergeance_usec; //Apply usec!

		//Apply the resulting time!
		timeval.tv_sec = (uint_64)(applyingtime/1000000); //Time in seconds!
		timeval.tv_usec = (uint_64)(applyingtime%1000000); //We have the amount of microseconds left!
		if (epochtoaccuratetime(&timeval,curtime)) //Convert back to apply it to the current time!
		{
			return 1; //Success!
		}
	}
	return 0; //Failed!
}

//Calculating relative time from the CMOS!
OPTINLINE void updateTimeDivergeance() //Update relative time to the clocks(time difference changes)! This is called when software changes the time/date!
{
	UniversalTimeOfDay tp;
	accuratetime savedtime,currenttime;
	CMOS_decodetime(&savedtime); //Get the currently stored time in the CMOS!
	if (CMOS.DATA.cycletiming) //Time is according to emulated system?
	{
		tp.tv_sec = 0; //Relative!
		tp.tv_usec = 0; //Relative!
		goto updatetimecycleaccurateRTC; //Update time emulated using the RTC's normal functionality!
	}
	if (getUniversalTimeOfDay(&tp)==0) //Time gotten?
	{
		updatetimecycleaccurateRTC:
		if (epochtoaccuratetime(&tp,&currenttime)) //Convert to accurate time!
		{
			calcDivergeance(&savedtime,&currenttime,&CMOS.DATA.timedivergeance,&CMOS.DATA.timedivergeance2); //Apply the new time divergeance!
			if (applyDivergeance(&currenttime,CMOS.DATA.timedivergeance,CMOS.DATA.timedivergeance2)) //Try if we're OK!
			{
				if (memcmp(&savedtime,&currenttime,(size_t)((ptrnum)&currenttime.dst-(ptrnum)&currenttime))) //Different?
				{
					dolog("CMOS","Time divergeance overflow due to too late/early time to contain!");
				}
			}
		}
	}
}

//Update the current Date/Time (based upon the refresh rate set) to the CMOS this runs at 64kHz!
double RTC_emulateddeltatiming = 0.0; //RTC remaining timing!
double RTC_timetick = 0.0; //The tick length in ns of a RTC tick!

void CMOS_updateActualTime()
{
	UniversalTimeOfDay tp;
	accuratetime currenttime;
	if (CMOS.DATA.cycletiming==0) //Normal timing?
	{
		if (getUniversalTimeOfDay(&tp) == 0) //Time gotten?
		{
			applytimedivergeanceRTC:
			if (epochtoaccuratetime(&tp,&currenttime)) //Converted?
			{
				//Apply time!
				applyDivergeance(&currenttime, CMOS.DATA.timedivergeance,CMOS.DATA.timedivergeance2); //Apply the new time divergeance!
				CMOS_encodetime(&currenttime); //Apply the new time to the CMOS!
			}
		}
	}
	else //Applying delta timing instead(cycle-accurate timing)?
	{
		CMOS.DATA.timedivergeance += RTC_emulateddeltatiming/1000000000.0; //Tick seconds!
		RTC_emulateddeltatiming = fmod(RTC_emulateddeltatiming,1000000000.0); //Remainder!
		double temp;
		temp = (double)(CMOS.DATA.timedivergeance2+(RTC_emulateddeltatiming/1000.0)); //Add what we can!
		RTC_emulateddeltatiming = fmod((double)RTC_emulateddeltatiming,1000.0); //Save remainder!
		if (temp>=1000000.0) //Overflow?
		{
			CMOS.DATA.timedivergeance += (temp/1000000.0); //Add second(s) on overflow!
			temp = fmod(temp,1000000.0); //Remainder!
		}
		CMOS.DATA.timedivergeance2 = (int_64)temp; //us to store!
		tp.tv_sec = 0; //Direct time!
		tp.tv_usec = 0; //Direct time!
		goto applytimedivergeanceRTC; //Apply the cycle-accurate time!
	}
}

void RTC_updateDateTime() //Called at 32kHz!
{
	//Update the time itself at the highest frequency of 32kHz!
	//Get time!
	byte lastsecond = CMOS.DATA.DATA80.info.RTC_Seconds; //Previous second value for alarm!
	RTC_emulateddeltatiming += RTC_timetick; //Add time to tick!

	if (((CMOS.DATA.DATA80.info.STATUSREGISTERB&SRB_ENABLECYCLEUPDATE)==0) && (dcc!=DIVIDERCHAIN_RESET)) //We're allowed to update the time(divider chain isn't reset too)?
	{
		CMOS_updateActualTime(); //Update the current actual time!
	}
	RTC_Handler(lastsecond); //Handle anything that the RTC has to handle!
}

double RTC_timepassed = 0.0;
void updateCMOS(double timepassed)
{
	RTC_timepassed += timepassed; //Add the time passed to get our time passed!
	if (RTC_timetick) //Are we enabled?
	{
		if (RTC_timepassed >= RTC_timetick) //Enough to tick?
		{
			for (;RTC_timepassed>=RTC_timetick;) //Still enough to tick?
			{
				RTC_timepassed -= RTC_timetick; //Ticked once!
				RTC_updateDateTime(); //Call our timed handler!
			}
		}
	}
}

uint_32 getGenericCMOSRate()
{
	INLINEREGISTER byte rate;
	rate = CMOS.DATA.DATA80.data[0xA]; //Load the rate register!
	rate &= 0xF; //Only the rate bits themselves are used!
	if ((rate) && (dcc!=DIVIDERCHAIN_DISABLED)) //To use us, also are we allowed to be ticking?
	{
		if (rate<3) //Rates 1&2 are actually the rate of 8&9!
		{
			--rate; //Rate is one less: rates 1&2 become 0&1 for patching!
			rate |= 8; //Convert rates 0&1 to rates 8&9!
		}
		--rate; //We're oprating at a rate of 32kHz, not 64kHz, so double the rate! This can be done because register A is always >= 3 at this stage(after patching the 1&2 rates).
		--rate; //Rate is one less(we're specifying a bit)!
		return (1<<rate); //The tap to look at(as a binary number) for a square wave to change state!
	}
	else //We're disabled?
	{
		return 0; //We're disabled!
	}
}

OPTINLINE void CMOS_onWrite(byte oldSRB) //When written to CMOS!
{
	if ((CMOS.ADDR==0xB) || (CMOS.ADDR==0xA)) //Might have changed IRQ8 functions!
	{
		updatedividerchain(); //Update the divider chain setting!
		CMOS.RateDivider = getGenericCMOSRate(); //Generic rate!
	}
	else if (CMOS.ADDR < 0xA) //Date/time might have been updated?
	{
		if ((CMOS.ADDR>5) || ((CMOS.ADDR&1)==0)) //Date/Time has been updated(not Alarm being set)?
		{
			updateTimeDivergeance(); //Update the relative time compared to current time!
		}
	}
	else if (CMOS.ADDR==0x32) //Century has been updated?
	{
		updateTimeDivergeance(); //Update the relative time compared to current time!
	}
	CMOS.Loaded = 1; //We're loaded now!
}

void loadCMOS()
{
	if (!(((BIOS_Settings.got_ATCMOS) && (((is_Compaq|is_XT|is_PS2)==0))) || (BIOS_Settings.got_CompaqCMOS && (is_Compaq && (is_PS2==0)))  || (BIOS_Settings.got_XTCMOS && is_XT) || (BIOS_Settings.got_PS2CMOS && is_PS2))) //XT/AT/Compaq/PS/2 CMOS?
	{
		loadCMOSDefaults(); //Load our default requirements!
		return;
	}
	else //Load BIOS CMOS!
	{
		if (is_PS2) //PS/2 CMOS?
		{
			memcpy(&CMOS.DATA, &BIOS_Settings.PS2CMOS, sizeof(CMOS.DATA)); //Copy to our memory!
		}
		else if (is_Compaq) //Compaq?
		{
			memcpy(&CMOS.DATA, &BIOS_Settings.CompaqCMOS, sizeof(CMOS.DATA)); //Copy to our memory!
		}
		else if (is_XT) //XT CMOS?
		{
			memcpy(&CMOS.DATA, &BIOS_Settings.XTCMOS, sizeof(CMOS.DATA)); //Copy to our memory!
		}
		else //AT CMOS?
		{
			memcpy(&CMOS.DATA, &BIOS_Settings.ATCMOS, sizeof(CMOS.DATA)); //Copy to our memory!
		}
	}

	//Apply the reset signal results(usually done when applying power to a computer)!
	CMOS.DATA.DATA80.data[0xC] = 0x00; //Register C is cleared when reset is asserted!
	CMOS.DATA.DATA80.info.STATUSREGISTERB &= ~0x78; //The interrupt settings and Square wave enable are cleared when reset is asserted!
	CMOS.DATA.DATA80.info.STATUSREGISTERA = (2<<4)|0x6; //Make sure the timer is properly counting! Load the Status register A defaults!

	//Initialize running data for making us tick correctly!
	updatedividerchain(); //Update the divider chain setting!
	CMOS.RateDivider = getGenericCMOSRate(); //Generic rate!

	CMOS.Loaded = 1; //The CMOS is loaded!
}

void saveCMOS()
{
	if (CMOS.Loaded==0) return; //Don't save when not loaded/initialised!
	if (is_PS2) //PS/2 CMOS?
	{
		memcpy(&BIOS_Settings.PS2CMOS, &CMOS.DATA, sizeof(CMOS.DATA)); //Copy the CMOS to BIOS!
		BIOS_Settings.got_PS2CMOS = 1; //We've saved an CMOS!
	}
	if (is_Compaq) //Compaq?
	{
		memcpy(&BIOS_Settings.CompaqCMOS, &CMOS.DATA, sizeof(CMOS.DATA)); //Copy the CMOS to BIOS!
		BIOS_Settings.got_CompaqCMOS = 1; //We've saved an CMOS!
	}
	else if (is_XT) //XT CMOS?
	{
		memcpy(&BIOS_Settings.XTCMOS, &CMOS.DATA, sizeof(CMOS.DATA)); //Copy the CMOS to BIOS!
		BIOS_Settings.got_XTCMOS = 1; //We've saved an CMOS!
	}
	else //AT CMOS?
	{
		memcpy(&BIOS_Settings.ATCMOS, &CMOS.DATA, sizeof(CMOS.DATA)); //Copy the CMOS to BIOS!
		BIOS_Settings.got_ATCMOS = 1; //We've saved an CMOS!
	}
	forceBIOSSave(); //Save the BIOS data!
}

byte XTRTC_translatetable[0x10] = {
0x80, //00: 1/1000 seconds
0x81, //01: 1/100 and 1/10 seconds
0x00, //02: seconds
0x02, //03: minutes
0x04, //04: hours
0x06, //05: day of week
0x07, //06: day of month
0x08, //07: month
0xFF, //08: RAM
0x09, //09: RAM(1/100 and 1/10 second), but map to year for easy updating!
0xFF, //0A: RAM
0xFF, //0B: RAM
0xFF, //0C: RAM
0xFF, //0D: RAM
0xFF, //0E: RAM
0xFF  //0F: RAM
}; //XT to CMOS translation table!

extern byte is_XT; //Are we an XT machine?

byte PORT_readCMOS(word port, byte *result) //Read from a port/register!
{
	byte data;
	byte isXT = 0;
	switch (port)
	{
	case 0x70: //CMOS_ADDR
		if (is_XT) return 0; //Not existant on XT systems!
		*result = CMOS.ADDR|(NMI<<7); //Give the address and NMI!
		return 1;
	case 0x71:
		if (is_XT) return 0; //Not existant on XT systems!
		readXTRTC: //XT RTC read compatibility
		if ((CMOS.ADDR&0x80)==0x00) //Normal data?
		{
			data = CMOS.DATA.DATA80.data[CMOS.ADDR]; //Give the data from the CMOS!
			if (CMOS.ADDR == 0xD) //Read only status register D?
			{
				CMOS.DATA.DATA80.data[0xD] = 0x80; //We now have valid data and RAM, when not already! This is according to the Moterola MC146818 chip documentation!
			}
			//Status register B&C are read-only!
		}
		else
		{
			switch (CMOS.ADDR & 0x7F) //What extended register?
			{
			case 0: //s10000?
				data = (CMOS.DATA.s10000&0xF0); //10000th seconds, high digit only!
				break;
			case 1: //s100?
				data = CMOS.DATA.s100; //100th/10th seconds!
				break;
			default: //Unknown?
				data = 0; //Unknown register!
				break;
			}
		}
		if (CMOS.ADDR == 0x0C) //Lower any interrupt flags set when this register is read? This allows new interrupts to fire!
		{
			//Enable all interrupts for RTC again?
			lowerirq(8); //Lower the IRQ, if raised!
			acnowledgeIRQrequest(8); //Acnowledge the IRQ, if needed!
			if ((data&0x70)&(CMOS.DATA.DATA80.info.STATUSREGISTERB&0x70)) data |= 0x80; //Set the IRQF bit when any interrupt is requested (PF==PIE==1, AF==AIE==1 or UF==UIE==1)
			CMOS.DATA.DATA80.data[0x0C] = 0x00; //Clear the interrupt raised flags to allow new interrupts to fire! Used to be &=0xF, but according to Bochs, the entire register is cleared!
		}
		CMOS.ADDR = 0xD; //Reset address!
		*result = data; //Give the data!
		return 1;
	//XT RTC support? MM58167B chip!
	case 0x240: //1/10000 seconds with TIMER.COM v1.2; 1/1000 according to docs.
	case 0x241: //1/100 seconds and 1/10 seconds
	case 0x242: //seconds
	case 0x243: //minutes
	case 0x244: //hours
	case 0x245: //day of week
	case 0x246: //day of month
	case 0x247: //month
	case 0x249: //1/100 seconds and 1/10 seconds latch according to docs, year in the case of TIMER.COM v1.2(HACK)!
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		isXT = 1; //From XT!
		CMOS.ADDR = XTRTC_translatetable[port&0xF]; //Translate the port to a compatible index!
		goto readXTRTC; //Read the XT RTC!
	//RAM latches!
	case 0x248: //1/10000 seconds RAM latch according to documentation! Only high part is used!
	case 0x24A: //seconds RAM latch
	case 0x24B: //minutes RAM latch
	case 0x24C: //hours RAM latch
	case 0x24D: //day of week RAM latch
	case 0x24E: //day of month RAM latch
	case 0x24F: //month RAM latch
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		*result = CMOS.DATA.extraRAMdata[port-0x248]; //Map to month for port 248?
		if (port==0x248) //High only?
		{
			*result &= 0xF0; //Mask off!
		}
		return 1;
		break;
	//Control registers of the chip:
	case 0x250: //Interrupt status Register
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		*result = 0; //Unimplemented atm!
		return 1; //Simply supported for now(plain RAM read)!
		break;
	case 0x251: //Interrupt control Register
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		*result = 0; //Unimplemented atm!
		return 1; //Simply supported for now(plain RAM read)!
		break;
	case 0x252: //Counter Reset
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		*result = 0; //Unimplemented atm!
		return 1; //Simply supported for now(plain RAM read)!
		break;
	case 0x253: //Latch/RAM Reset
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		*result = 0; //Unimplemented atm!
		return 1; //Simply supported for now(plain RAM read)!
		break;
	case 0x254: //Status Bit
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		*result = 0; //Never updating the status(bit 0)!
		return 1;
		break;
	case 0x255: //"GO" Command
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		*result = 0; //Unimplemented atm!
		return 1; //Simply supported for now(plain RAM read)!
		break;
	case 0x256: //Standby Interrupt
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		*result = 0; //Unimplemented atm!
		return 1; //Simply supported for now(plain RAM read)!
		break;
	case 0x257: //Test Mode
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		*result = 0; //Unimplemented atm!
		return 1; //Simply supported for now(plain RAM read)!
		break;
	}
	return 0; //None for now!
}

byte PORT_writeCMOS(word port, byte value) //Write to a port/register!
{
	byte temp;
	byte isXT = 0;
	byte originalvalue;
	byte oldSRB;
	switch (port)
	{
	case 0x70: //CMOS ADDR
		if (is_XT) return 0; //Not existant on XT systems!
		CMOS.ADDR = (value&0x7F); //Take the value!
		NMI = ((value&0x80)>>7); //NMI?
		return 1;
		break;
	case 0x71:
		if (is_XT) return 0; //Not existant on XT systems!
		writeXTRTC: //XT RTC write compatibility
		originalvalue = value; //Save original value for comparison!

		oldSRB = CMOS.DATA.DATA80.info.STATUSREGISTERB; //Old SRB!

		//Write back the destination data!
		if ((CMOS.ADDR & 0x80)==0x00) //Normal data?
		{
			if ((CMOS.ADDR!=0xC) && (CMOS.ADDR!=0xD)) //Read only values?
			{
				if (CMOS.ADDR==0xA) //Register A has a read-only bit!
				{
					value &= 0x7F; //Only allow the writable bits!
					value |= (CMOS.DATA.DATA80.data[0xA]&SRA_UPDATEINPROGRESS); //Read-only bit!
				}
				else if (CMOS.ADDR==0xB) //Special time update functionality?
				{
					if ((CMOS.DATA.DATA80.data[0xB]&SRB_ENABLECYCLEUPDATE) && ((value&SRB_ENABLECYCLEUPDATE)==0x00)) //We've halted time and starting it again? Update the RTC timing that's synchronized!
					{
						updateTimeDivergeance(); //Make sure the divergeance is set accordingly when restarting the RTC clock!
					}
				}
				if ((CMOS.ADDR==0xF) && isDebuggingPOSTCodes()) //CMOS shutdown byte?
				{
					dolog("debugger","Shutdown status: %02X",value); //Log the shutdown value!
				}
				CMOS.DATA.DATA80.data[CMOS.ADDR] = value; //Give the data from the CMOS!
				if (CMOS.ADDR==0x32) //Century?
				{
					CMOS.DATA.centuryisbinary = (encodeBCD8(decodeBCD8(value,0),0)!=value)?1:0; //Do we require being used as binary?
				}
			}
		}
		else
		{
			switch (CMOS.ADDR & 0x7F) //What extended register?
			{
			case 0: //s10000?
				CMOS.DATA.s10000 = (value&0xF0); //10000th seconds!
				break;
			case 1: //s100/s10?
				CMOS.DATA.s100 = value; //100th/10th seconds!
				break;
			default: //Unknown?
				//Unknown register! Can't write!
				break;
			}
		}
		CMOS_onWrite(oldSRB); //On write!
		CMOS.ADDR = 0xD; //Reset address!		
		return 1;
		break;
	//XT RTC support!
	case 0x240: //1/10000 seconds with TIMER.COM v1.2; 1/1000 according to docs(correct: 10/10000=1/1000, but it's in the high nibble, low nibble disabled).
	case 0x241: //1/100 seconds and 1/10 seconds
	case 0x242: //seconds
	case 0x243: //minutes
	case 0x244: //hours
	case 0x245: //day of week
	case 0x246: //day of month
	case 0x247: //month
	case 0x249: //1/100 seconds and 1/10 seconds latch according to docs, year in the case of TIMER.COM v1.2(HACK)!
		if (is_XT==0) return 0; //Not existant on the AT and higher!
		isXT = 1; //From XT!
		CMOS.ADDR = XTRTC_translatetable[port & 0xF]; //Translate the port to a compatible index!
		goto writeXTRTC; //Read the XT RTC!
	//Latches to XT CMOS RAM!
	//RAM latches!
	case 0x248: //1/1000 seconds RAM latch according to documentation, map to RAM for TIMER.COM v1.2!
		value &= 0xF0; //Mask off the low nibble, which doesn't exist!
	case 0x24A: //seconds RAM latch
	case 0x24B: //minutes RAM latch
	case 0x24C: //hours RAM latch
	case 0x24D: //day of week RAM latch
	case 0x24E: //day of month RAM latch
	case 0x24F: //month RAM latch
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		CMOS.DATA.extraRAMdata[port-0x248] = value; //Map to month for port 248 instead!
		return 1;
		break;
	//Rest registers of the chip:
	case 0x250: //Interrupt status Register (R/O)
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		//Unimplemented atm!
		return 1;
		break;
	case 0x251: //Interrupt control Register
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		//Unimplemented atm!
		return 1;
		break;
	case 0x252: //Counter Reset
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		//Unimplemented atm!
		return 1;
		break;
	case 0x253: //Latch/RAM Reset
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		//Unimplemented atm!
		return 1;
		break;
	case 0x254: //Status Bit
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		//Unimplemented atm!
		return 1;
		break;
	case 0x255: //"GO" Command
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		//Unimplemented atm!
		return 1;
		break;
	case 0x256: //Standby Interrupt
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		//Unimplemented atm!
		return 1;
		break;
	case 0x257: //Test Mode
		if (is_XT == 0) return 0; //Not existant on the AT and higher!
		//Unimplemented atm!
		return 1;
		break;
	default: //Unknown?
		break; //Do nothing!
	}
	return 0; //Unsupported!
}

void initCMOS() //Initialises CMOS (apply solid init settings&read init if possible)!
{
	CMOS.ADDR = 0; //Reset!
	NMI = 1; //Reset: Disable NMI interrupts!
	memset(&CMOS,0,sizeof(CMOS)); //Make sure we're fully initialized always!
	loadCMOS(); //Load the CMOS from disk OR defaults!

	//Register our I/O ports!
	register_PORTIN(&PORT_readCMOS);
	register_PORTOUT(&PORT_writeCMOS);
	XTMode = 0; //Default: not XT mode!
	RTC_timepassed = RTC_emulateddeltatiming = 0.0; //Initialize our timing!
	RTC_timetick = 1000000000.0/32768.0; //We're ticking at a frequency of ~65kHz(65535Hz signal, which is able to produce a square wave as well at that frequency?)!
}