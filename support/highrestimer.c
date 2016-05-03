#include "headers/types.h" //Basic types!
#include "headers/support/highrestimer.h" //Our own typedefs etc.
#include "headers/support/log.h" //Logging support!
#include "headers/support/locks.h" //Locking support!

double tickresolution = 0.0f; //Our tick resolution, initialised!
byte tickresolution_win_SDL = 0; //Force SDL rendering?

float msfactor, usfactor, nsfactor; //The factors!
float msfactorrev, usfactorrev, nsfactorrev; //The factors reversed!

void initHighresTimer()
{
#ifdef __psp__
		tickresolution = sceRtcGetTickResolution(); //Get the tick resolution, as defined on the PSP!
#else
#ifdef _WIN32
		LARGE_INTEGER tickresolution_win;
		if (QueryPerformanceFrequency(&tickresolution_win))
		{
			tickresolution = (double)tickresolution_win.QuadPart; //Apply the tick resolution!
			tickresolution_win_SDL = 0; //Don't force SDL!
		}
		else //SDL fallback?
		{
			tickresolution = 1000.0f;
			tickresolution_win_SDL = 1; //Force SDL!
		}
#else
		tickresolution = 1000.0f; //We have a resolution in ms as given by SDL!
#endif
#endif
		//Calculate needed precalculated factors!
		usfactor = (float)(1.0f/tickresolution)*US_SECOND; //US factor!
		nsfactor = (float)(1.0f/tickresolution)*NS_SECOND; //NS factor!
		msfactor = (float)(1.0f/tickresolution)*MS_SECOND; //MS factor!
		usfactorrev = 1.0f/usfactor; //Reverse!
		nsfactorrev = 1.0f/nsfactor; //Reverse!
		msfactorrev = 1.0f/msfactor; //Reverse!
}

OPTINLINE u64 getcurrentticks() //Retrieve the current ticks!
{
#ifdef __psp__
	u64 result = 0; //The result!
	if (!sceRtcGetCurrentTick(&result)) //Try to retrieve current ticks as old ticks until we get it!
	{
		return result; //Give the result!
	}
	return 0; //Give the result: ticks passed!
#else
#ifdef _WIN32
	if (tickresolution_win_SDL) goto forcewinsdl; //Forcing SDL?
	LARGE_INTEGER temp;
	if (!QueryPerformanceCounter(&temp)) return 0; //Invalid result?
	return temp.QuadPart; //Give the result by the performance counter of windows!
	forcewinsdl: //Force SDL usage of ticks!
#endif
#endif
	return (u64)SDL_GetTicks(); //Give the ticks passed using SDL default handling!
}

void initTicksHolder(TicksHolder *ticksholder)
{
	memset(ticksholder, 0, sizeof(*ticksholder)); //Clear the holder!}
	ticksholder->newticks = getcurrentticks(); //Initialize the ticks to the current time!
}

void ticksholder_AVG(TicksHolder *ticksholder)
{
	ticksholder->avg = 1; //Enable average meter!
}

OPTINLINE u64 getrealtickspassed(TicksHolder *ticksholder)
{
    register u64 temp;
	register u64 currentticks = getcurrentticks(); //Fist: get current ticks to be sure we're right!
	//We're not initialising/first call?
	temp = ticksholder->newticks; //Move new ticks to old ticks! Store it for quicker reference later on!
	ticksholder->oldticks = temp; //Store the old ticks!
	ticksholder->newticks = currentticks; //Set current ticks as new ticks!
	if (currentticks<temp)//Overflown time?
	{
	    //Temp is already equal to oldticks!
	    temp -= currentticks; //Difference between the numbers(old-new=difference)!
		currentticks = ~0; //Max to substract from instead of the current ticks!
	}
	currentticks -= temp; //Substract the old ticks for the difference!
	return currentticks; //Give the result: amount of ticks passed!
}

OPTINLINE uint_64 gettimepassed(TicksHolder *ticksholder, float secondfactor, float secondfactorreversed)
{
	register float result;
	register float tickspassed;
	tickspassed = (float)getrealtickspassed(ticksholder); //Start with checking the current ticks!
	tickspassed += ticksholder->ticksrest; //Add the time we've left unused last time!
	result = floor(tickspassed*secondfactor); //The ammount of ms that has passed as precise as we can use!
	tickspassed -= (result*secondfactorreversed); //The ticks left unprocessed this call!
	ticksholder->ticksrest = tickspassed; //Add the rest ticks unprocessed to the next time we're counting!
	if (ticksholder->avg) //Average enabled?
	{
		ticksholder->avg_sumpassed += result; //Add to the sum!
		++ticksholder->avg_oldtimes; //One time more!
		return SAFEDIV(ticksholder->avg_sumpassed,ticksholder->avg_oldtimes); //Give the ammount passed averaged!
	}
	return (uint_64)result; //Ordinary result!
}

uint_64 getmspassed(TicksHolder *ticksholder) //Get ammount of ms passed since last use!
{
	return gettimepassed(ticksholder, msfactor,msfactorrev); //Factor us!
}

uint_64 getuspassed(TicksHolder *ticksholder) //Get ammount of ms passed since last use!
{
	return gettimepassed(ticksholder,usfactor,usfactorrev); //Factor us!
}

uint_64 getnspassed(TicksHolder *ticksholder)
{
	return gettimepassed(ticksholder,nsfactor,nsfactorrev); //Factor ns!
}

uint_64 getmspassed_k(TicksHolder *ticksholder) //Same as getuspassed, but doesn't update the start of timing, allowing for timekeeping normally.
{
	TicksHolder temp;
	memcpy(&temp, ticksholder, sizeof(temp)); //Copy the old one!
	return gettimepassed(&temp, msfactor, msfactorrev); //Factor us!
}

uint_64 getuspassed_k(TicksHolder *ticksholder) //Same as getuspassed, but doesn't update the start of timing, allowing for timekeeping normally.
{
	TicksHolder temp;
	memcpy(&temp,ticksholder,sizeof(temp)); //Copy the old one!
	return gettimepassed(&temp, usfactor, usfactorrev); //Factor us!
}

uint_64 getnspassed_k(TicksHolder *ticksholder) //Same as getuspassed, but doesn't update the start of timing, allowing for timekeeping normally.
{
	TicksHolder temp;
	memcpy(&temp,ticksholder,sizeof(temp)); //Copy the old one!
	return gettimepassed(&temp, nsfactor, nsfactorrev); //Factor us!
}

void startHiresCounting(TicksHolder *ticksholder)
{
	getrealtickspassed(ticksholder); //Start with counting!
}

void stopHiresCounting(char *src, char *what, TicksHolder *ticksholder)
{
	char time[30]; //Some time holder!
	uint_64 passed = getuspassed(ticksholder); //Get the time that has passed!
	bzero(time,sizeof(time)); //Init holder!
	convertTime(passed,&time[0]); //Convert the time!
	dolog(src,"Counter %s took %s",what,time); //Log it!
}

void convertTime(uint_64 time, char *holder) //Convert time to hh:mm:ss:s100.s1000.s1k!
{
	uint_32 h, m, s, s100, s1000, s1k;
	h = (uint_32)(time/3600000000ll); //Hours!
	time -= h*3600000000ll; //Left!
	m = (uint_32)(time/60000000ll); //Minutes!
	time -= m*60000000ll; //Left!
	s = (uint_32)(time/1000000ll); //Seconds!
	time -= s*1000000ll; //Left!
	s100 = (uint_32)(time/10000ll); //s100!
	time -= s100*10000ll;
	s1000 = (uint_32)(time/1000ll); //s1000!
	time -= s1000*1000ll; //Left!
	s1k = (uint_32)time; //All that's left!
	sprintf(holder,"%i:%02i:%02i:%02i.%i.%04i",h,m,s,s100,s1000,s1k); //Generate the final text!
}