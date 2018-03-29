#include "headers/types.h" //Basic types!
#include "headers/support/sounddoublebuffer.h" //Double buffered sound support!
#include "headers/emu/sound.h" //Sound output support!
#include "headers/support/signedness.h" //Sign support!
#include "headers/support/log.h" //Logging support!
#include "headers/hardware/ports.h" //I/O support!
#include "headers/hardware/adlib.h" //Adlib card has more ports with Sound Blasters!
#include "headers/hardware/pic.h" //Interrupt support!
#include "headers/hardware/8237A.h" //DMA support!
#include "headers/hardware/midi/midi.h" //MIDI support!
#include "headers/support/highrestimer.h" //Ticks holder support for real-time recording!
#include "headers/support/wave.h" //Wave file logging support!

#define MHZ14_TICK 644
#define __SOUNDBLASTER_SAMPLERATE (MHZ14/MHZ14_TICK)
#define __SOUNDBLASTER_SAMPLEBUFFERSIZE 2048
#define SOUNDBLASTER_VOLUME 100.0f
//Size of the input buffer of the DSP chip!
#define __SOUNDBLASTER_DSPINDATASIZE 16
//Big enough output buffer for all ranges available!
#define __SOUNDBLASTER_DSPOUTDATASIZE 0x10000

//IRQ/DMA assignments! Use secondary IRQ8(to prevent collisions with existing hardware!) Bochs says IRQ5? Dosbox says IRQ7?
//8-bit IRQ&DMA!
#define __SOUNDBLASTER_IRQ8 0x15
#define __SOUNDBLASTER_DMA8 1

#define ADPCM_FORMAT_NONE 0x00
#define ADPCM_FORMAT_2BIT 0x01
#define ADPCM_FORMAT_26BIT 0x02
#define ADPCM_FORMAT_4BIT 0x03

//Sound Blaster version used!
#define SB_VERSION15 0x0105
#define SB_VERSION20 0x0200

#define SB_VERSION SOUNDBLASTER.version

#define MIN_ADAPTIVE_STEP_SIZE 0

//Record a test wave!
//#define RECORD_TESTWAVE
//Log what we record?
//#define LOG_RECORDING

//Enable below define to log all command bytes sent.
//#define SOUNDBLASTER_LOG

enum {
	DSP_S_RESET, DSP_S_RESET_WAIT, DSP_S_NORMAL
}; //DSP state for reset detection!

struct
{
	word baseaddr;
	SOUNDDOUBLEBUFFER soundbuffer; //Outputted sound to render!
	FIFOBUFFER *DSPindata; //Data to be read from the DSP!
	FIFOBUFFER *DSPoutdata; //Data to be rendered for the DSP!
	byte resetport;
	byte command; //The current command we're processing (0 for none)
	byte commandstep; //The step within the command!
	uint_32 dataleft; //The position(in bytes left) within the command during the data phase!
	byte busy; //Are we busy (not able to receive data/commands)?
	byte IRQ8Pending; //Is a 8-bit IRQ pending?
	byte DREQ; //Our current DREQ signal for transferring data!
	word wordparamoutput;
	uint_32 silencesamples; //Silence samples left!
	byte muted; //Is speaker output disabled?
	byte singen; //Sine wave generator enabled?
	DOUBLE singentime; //Sine wave generator position in time!
	byte DMADisabled; //DMA not paused?
	byte ADPCM_format; //Format of the ADPCM data, if used!
	byte ADPCM_reference; //The current by of ADPCM is the reference?
	byte ADPCM_currentreference; //Current reference byte!
	int_32 ADPCM_stepsize; //Current ADPCM step size!
	byte reset; //Current reset state!
	word version; //The version number we are emulating!
	byte AutoInit; //The current AutoInit setting to use!
	byte AutoInitBuf; //The buffered autoinit setting to be applied when starting!
	word AutoInitBlockSize; //Auto-init block size, as set by the Set DMA Block Size command for Auto-Init commands!
	byte TestRegister; //Sound Blaster 2.01+ Test register!
	DOUBLE frequency; //The frequency we're currently rendering at!
	byte DirectADC; //Special ADC condition for Sound Blaster prior to SB16!
	TicksHolder recordingtimer; //Real-time recording support!
	byte recordedsample; //Last recorded sample, updated real-time!
} SOUNDBLASTER; //The Sound Blaster data!

extern byte specialdebugger; //Enable special debugger input?

uint_32 soundblaster_soundtiming = 0;
DOUBLE soundblaster_soundtick = 0.0;
DOUBLE soundblaster_sampletiming = 0.0, soundblaster_recordingtiming = 0.0, soundblaster_sampletick = 0.0;

DOUBLE soundblaster_IRR = 0.0, soundblaster_resettiming = 0.0; //No IRR nor reset requested!

byte sb_leftsample=0x80, sb_rightsample=0x80; //Two stereo samples, silence by default!

#ifdef LOG_RECORDING
WAVEFILE *sb_output=NULL;
uint_32 sb_recordingrate = 0;
#endif

OPTINLINE void SoundBlaster_IRQ8()
{
	SOUNDBLASTER.IRQ8Pending |= 2; //We're actually pending!
	raiseirq(__SOUNDBLASTER_IRQ8); //Trigger the IRQ for 8-bit transfers!
}

OPTINLINE void SoundBlaster_FinishedReset()
{
	writefifobuffer(SOUNDBLASTER.DSPindata, 0xAA); //We've reset!
	fifobuffer_gotolast(SOUNDBLASTER.DSPindata); //Force the data to the user!
	SOUNDBLASTER.reset = DSP_S_NORMAL; //Normal execution of the DSP!
}

void tickSoundBlasterRecording()
{
	#ifdef LOG_RECORDING
	if (sb_output) //Recording?
	{
		if (sb_recordingrate!=(uint_32)SOUNDBLASTER.frequency) //Rate changed?
		{
			closeWAV(&sb_output); //Close: we're to restart!
		}
	}
	if (sb_output==NULL) //Not recording yet or changed rate?
	{
		lockaudio();
		sb_output = createWAV(get_soundrecording_filename(),1,(uint_32)SOUNDBLASTER.frequency); //Start recording to this file!
		sb_recordingrate = (uint_32)SOUNDBLASTER.frequency; //The new rate!
		unlockaudio();
	}
	if (sb_output) //Valid output?
	{
		word sample16;
		sample16 = SOUNDBLASTER.recordedsample; //The recorded sample!
		sample16 ^= 0x80; //Flip the sign bit!
		sample16 <<= 8; //Multiply into range!
		sample16 |= (sample16 & 0xFF00) ? 0xFF : 0x00; //Bit fill!
		writeWAVMonoSample(sb_output,sample16); //Write the sample to the log file!
	}
	#endif
}

extern byte haswindowactive; //For detecting paused operation!

void updateSoundBlaster(DOUBLE timepassed, uint_32 MHZ14passed)
{
	
	DOUBLE dummy;
	DOUBLE temp;
	byte activeleft, activeright;
	DOUBLE soundblaster_recordedpassed;
	if (SOUNDBLASTER.baseaddr == 0) return; //No game blaster?

	//Check for pending IRQ request!
	if (unlikely(soundblaster_IRR > 0.0)) //Requesting?
	{
		soundblaster_IRR -= timepassed; //Substract time!
		if (unlikely(soundblaster_IRR <= 0.0)) //Expired?
		{
			//Execute Soft IRR after the requested timeout has passed!
			writefifobuffer(SOUNDBLASTER.DSPindata, 0xAA); //Acnowledged!
			fifobuffer_gotolast(SOUNDBLASTER.DSPindata); //Give the result!
			SoundBlaster_IRQ8();
		}
	}

	if (unlikely(soundblaster_resettiming > 0.0)) //Requesting?
	{
		soundblaster_resettiming -= timepassed; //Substract time!
		if (unlikely(soundblaster_resettiming <= 0.0)) //Expired?
		{
			SoundBlaster_FinishedReset(); //Finished the reset!
		}
	}

	soundblaster_recordedpassed = getnspassed(&SOUNDBLASTER.recordingtimer); //Tick the recording timer real-time!
	if (unlikely(haswindowactive&0x10)) {soundblaster_recordedpassed = 0.0; haswindowactive |= ~0x20;} //Fully active again?

	#ifdef RECORD_TESTWAVE
	//For testing!
	sword sample;
	static float recordtime = 0.0f;
	#endif

	if (unlikely(SOUNDBLASTER.DREQ || SOUNDBLASTER.silencesamples)) //Transaction busy?
	{
		//Play audio normally using timed output!
		if (likely(soundblaster_sampletick)) //Valid to time?
		{
			soundblaster_sampletiming += (SOUNDBLASTER.DREQ&0x10)?soundblaster_recordedpassed:timepassed; //Tick time or real-time(for recording)!
			if (unlikely((soundblaster_sampletiming>=soundblaster_sampletick) && (soundblaster_sampletick>0.0))) //Expired?
			{
				for (;soundblaster_sampletiming>=soundblaster_sampletick;) //A sample to play?
				{
					if (SOUNDBLASTER.silencesamples) //Silence requested?
					{
						sb_leftsample = sb_rightsample = 0x80; //Silent sample!
						if (--SOUNDBLASTER.silencesamples == 0) //Decrease the sample counter! If expired, fire IRQ!
						{
							SoundBlaster_IRQ8(); //Fire the IRQ!
							SOUNDBLASTER.DMADisabled |= 1; //We're a paused DMA transaction automatically!
						}
					}
					else //Audio playing?
					{
						if (readfifobuffer(SOUNDBLASTER.DSPoutdata, &sb_leftsample)) //Mono sample read?
						{
							sb_rightsample = sb_leftsample; //Render the new mono sample!
						}

						#ifdef RECORD_TESTWAVE
						sample = (sword)(sinf(2.0f*PI*1.0f*recordtime)*(SHRT_MAX/2.0)); //Use a test wave instead!
						recordtime += (1.0f/SOUNDBLASTER.frequency); //Tick time by one sample!
						recordtime = fmodf(recordtime,1.0f); //Wrap around a second!
						SOUNDBLASTER.recordedsample = ((signed2unsigned16(sample)>>8)^0x80); //Test sample to use!
						#else
						SOUNDBLASTER.recordedsample = (byte)(((word)getRecordedSampleL8u()+(word)getRecordedSampleR8u())*0.5f); //Update recording samples in real-time, mono!
						#endif

						tickSoundBlasterRecording();

						if (SOUNDBLASTER.command==0x20) //Direct ADC?
						{
							writefifobuffer(SOUNDBLASTER.DSPindata, SOUNDBLASTER.recordedsample); //Give the current sample!
							fifobuffer_gotolast(SOUNDBLASTER.DSPindata); //Give the result!
							SOUNDBLASTER.command = 0; //Finished!
						}

						if (fifobuffer_freesize(SOUNDBLASTER.DSPoutdata)==__SOUNDBLASTER_DSPOUTDATASIZE) //Empty buffer? We've finished rendering the samples specified!
						{
							//Time played audio that's ready!
							if (SOUNDBLASTER.DREQ && (SOUNDBLASTER.DREQ & 2)) //Paused until the next sample?
							{
								SOUNDBLASTER.DREQ &= ~2; //Start us up again, if allowed!
							}
						}
					}
					if (SOUNDBLASTER.DREQ&4) //Timing?
					{
						SOUNDBLASTER.DREQ &= ~4; //We're done timing, start up DMA again, if allowed!
					}
					soundblaster_sampletiming -= soundblaster_sampletick; //A sample has been ticked!
				}
			}
		}
	}
	else //Not requesting playback/recording?
	{
		//Record audio normally/silenced using timed output!
		if (likely(soundblaster_sampletick)) //Sample ticking?
		{
			soundblaster_sampletiming += timepassed; //Tick time or real-time(for recording)!
			if (unlikely((soundblaster_sampletiming>=soundblaster_sampletick) && (soundblaster_sampletick>0.0))) //Expired?
			{
				for (;soundblaster_sampletiming>=soundblaster_sampletick;) //A sample to play?
				{
					if (SOUNDBLASTER.silencesamples) //Silence requested?
					{
						sb_leftsample = sb_rightsample = 0x80; //Silent sample!
						if (--SOUNDBLASTER.silencesamples == 0) //Decrease the sample counter! If expired, fire IRQ!
						{
							SoundBlaster_IRQ8(); //Fire the IRQ!
							SOUNDBLASTER.DMADisabled |= 1; //We're a paused DMA transaction automatically!
						}
					}
					else //Audio recording at hardware rate?
					{
						#ifdef RECORD_TESTWAVE
						sample = (sword)(sinf(2.0f*PI*1.0f*recordtime)*(SHRT_MAX/2.0)); //Use a test wave instead!
						recordtime += (1.0f/SOUNDBLASTER.frequency); //Tick time!
						recordtime = fmodf(recordtime,1.0f); //Wrap around a second!
						SOUNDBLASTER.recordedsample = ((signed2unsigned16(sample)>>8)^0x80); //Test sample to use!
						#else
						SOUNDBLASTER.recordedsample = (byte)(((word)getRecordedSampleL8u()+(word)getRecordedSampleR8u())*0.5f); //Update recording samples in real-time, mono!
						#endif
						tickSoundBlasterRecording();
						soundblaster_sampletiming -= soundblaster_sampletick; //A sample has been ticked!
					}	
				}
			}
		}
	}

	if (unlikely(SOUNDBLASTER.singen)) //Diagnostic Sine wave generator enabled?
	{
		sb_leftsample = sb_rightsample = 0x80+(byte)(sin(2 *PI*2000.0f*SOUNDBLASTER.singentime) * (float)0x7F); //Give a full wave at the requested speed!
		SOUNDBLASTER.singentime += timepassed; //Tick the samples processed!
		temp = SOUNDBLASTER.singentime*2000.0f; //Calculate for overflow!
		if (temp >= 1.0) { //Overflow?
			#ifdef IS_LONGDOUBLE
			SOUNDBLASTER.singentime = modfl(temp, &dummy) / 2000.0f; //Protect against overflow by looping!
			#else
			SOUNDBLASTER.singentime = modf(temp, &dummy) / 2000.0f; //Protect against overflow by looping!
			#endif
		}
	}

	if (SOUNDBLASTER.muted) //Muted?
	{
		activeleft = activeright = 0x80; //Muted output!
	}
	else
	{
		activeleft = sb_leftsample; //Render the current left sample!
		activeright = sb_rightsample; //Render the current right sample!
	}

	//Finally, render any rendered Sound Blaster output to the renderer at the correct rate!
	//Sound Blaster sound output
	soundblaster_soundtiming += MHZ14passed; //Get the amount of time passed!
	if (unlikely(soundblaster_soundtiming >= MHZ14_TICK))
	{
		for (;soundblaster_soundtiming >= MHZ14_TICK;)
		{
			//Now push the samples to the output!
			writeDoubleBufferedSound16(&SOUNDBLASTER.soundbuffer, (activeright<<8) | activeleft); //Output the sample to the renderer!
			soundblaster_soundtiming -= MHZ14_TICK; //Decrease timer to get time left!
		}
	}
}

byte SoundBlaster_soundGenerator(void* buf, uint_32 length, byte stereo, void *userdata) //Generate a sample!
{
	uint_32 c;
	c = length; //Init c!

	static word last = 0x8080; //Start with silence!
	INLINEREGISTER word buffer;

	SOUNDDOUBLEBUFFER *doublebuffer = (SOUNDDOUBLEBUFFER *)userdata; //Our double buffered sound input to use!
	int_32 mono_converter;
	byte *data_buffer;
	data_buffer = (byte *)buf; //The data in correct samples!
	if (stereo) //Stereo processing?
	{
		for (;;) //Fill it!
		{
			//Left and right samples are the same: we're a mono signal!
			readDoubleBufferedSound16(doublebuffer, &last); //Generate a stereo sample if it's available!
			buffer = last; //Load the last sample for processing!
			*data_buffer++ = (byte)buffer; //Load the last generated sample(left)!
			buffer >>= 8; //Shift low!
			*data_buffer++ = (byte)buffer; //Load the last generated sample(right)!
			if (!--c) return SOUNDHANDLER_RESULT_FILLED; //Next item!
		}
	}
	else //Mono processing?
	{
		for (;;) //Fill it!
		{
			//Left and right samples are the same: we're a mono signal!
			readDoubleBufferedSound16(doublebuffer, &last); //Generate a stereo sample if it's available!
			buffer = last; //Load the last sample for processing!
			buffer ^= 0x8080; //Convert to signed values!
			mono_converter = unsigned2signed8((byte)buffer); //Load the last generated sample(left)!
			buffer >>= 8; //Shift low!
			mono_converter += unsigned2signed8((byte)buffer); //Load the last generated sample(right)!
			mono_converter = LIMITRANGE(mono_converter, -128, 127); //Clip our data to prevent overflow!
			mono_converter ^= 0x80; //Convert back to unsigned value!
			*data_buffer++ = (byte)mono_converter; //Save the sample and point to the next mono sample!
			if (!--c) return SOUNDHANDLER_RESULT_FILLED; //Next item!
		}
	}
}

OPTINLINE void DSP_startParameterADPCM(byte command, byte format, byte usereference, byte AutoInit)
{
	SOUNDBLASTER.commandstep = 0; //We're at the parameter phase!
	SOUNDBLASTER.command = (int)command; //Starting this command!
	SOUNDBLASTER.dataleft = 0; //counter of parameters!
	SOUNDBLASTER.ADPCM_reference = usereference; //Are we starting with a reference?
	SOUNDBLASTER.ADPCM_format = format; //The ADPCM format to use!
	SOUNDBLASTER.AutoInitBuf = AutoInit; //Buffer it until we use it!
}

OPTINLINE void SoundBlaster_DetectDMALength(byte command, word length)
{
	switch (command) //What command?
	{
	case 0x14: //DMA DAC, 8-bit
	case 0x16: //DMA DAC, 2-bit ADPCM
	case 0x17: //DMA DAC, 2-bit ADPCM reference
	case 0x24: //DMA ADC, 8-bit
	case 0x2C: //Auto-Initialize DMA ADC, 8-bit
	case 0x74: //DMA DAC, 4-bit ADPCM
	case 0x75: //DMA DAC, 4-bit ADPCM Reference
	case 0x76: //DMA DAC, 2.6-bit ADPCM
	case 0x77: //DMA DAC, 2.6-bit ADPCM Reference
	case 0x7D: //Auto-Initialize DMA DAC, 4-bit ADPCM Reference
	case 0x7F: //Auto-Initialize DMA DAC, 2.6-bit ADPCM Reference
		SOUNDBLASTER.dataleft = length + 1; //The length of the DMA transfer to play back, in bytes!
		break;
	default: //Unknown length?
			 //Ignore the transfer setting!
		break;
	}
}

OPTINLINE void DSP_startDMADAC(byte autoinitDMA, byte isRecording)
{
	SOUNDBLASTER.DREQ = 1|((isRecording&1)<<4); //Raise: we're outputting data for playback!
	if ((SOUNDBLASTER.DMADisabled&1) || autoinitDMA) //DMA Disabled?
	{
		SOUNDBLASTER.DMADisabled &= ~1; //Start the DMA transfer fully itself!
	}
	SOUNDBLASTER.commandstep = 1; //Goto step 1!
	SOUNDBLASTER.AutoInit = SOUNDBLASTER.AutoInitBuf; //Apply auto-init setting, when supported!
	if (autoinitDMA) //Autoinit?
	{
		SOUNDBLASTER.wordparamoutput = SOUNDBLASTER.AutoInitBlockSize; //Apply auto init to our size!
	}
	SoundBlaster_DetectDMALength((byte)SOUNDBLASTER.command, SOUNDBLASTER.wordparamoutput); //The length of the DMA transfer to play back, in bytes!
}

extern byte MPU_ready; //MPU installed?

#ifdef SOUNDBLASTER_LOG
#define SB2COMMAND if (SOUNDBLASTER.version<SB_VERSION20) { SOUNDBLASTER.command = 0; /*Invalid command!*/ if (specialdebugger) {dolog("SoundBlaster", "Unknown command: %02X@ver. %04X", command, SOUNDBLASTER.version);} return; /*Unsupported version*/ }
#define SB_LOGCOMMAND if (specialdebugger){dolog("SoundBlaster", "Command: %02X@ver. %04X", command, SOUNDBLASTER.version);}
#define SB_LOGINVCOMMAND if (specialdebugger){dolog("SoundBlaster", "Invalid Command: %02X@ver. %04X", command, SOUNDBLASTER.version);}
#else
#define SB2COMMAND if (SOUNDBLASTER.version<SB_VERSION20) { SOUNDBLASTER.command = 0; /*Invalid command!*/ return; /*Unsupported version*/ }
#define SB_LOGCOMMAND
#define SB_LOGINVCOMMAND
#endif

OPTINLINE void DSP_writeCommand(byte command)
{
	byte ADPCM_reference = 0; //ADPCM reference byte is used?
	byte AutoInit = 0; //Auto initialize command?
	switch (command) //What command?
	{
	case 0x10: //Direct DAC, 8-bit
		SB_LOGCOMMAND
		SOUNDBLASTER.command = 0x10; //Enable direct DAC mode!
		break;
	case 0x1C: //Auto-Initialize DMA DAC, 8-bit(DSP 2.01+)
		SB2COMMAND
		AutoInit = 1; //Auto initialize command instead!
	case 0x14: //DMA DAC, 8-bit
		SOUNDBLASTER.commandstep = 0; //We're at the parameter phase!
		SOUNDBLASTER.command = 0x14; //Starting this command!
		SOUNDBLASTER.dataleft = 0; //counter of parameters!
		SOUNDBLASTER.DREQ = 0; //Disable DMA!
		SOUNDBLASTER.ADPCM_format = ADPCM_FORMAT_NONE; //Plain samples!
		SOUNDBLASTER.AutoInitBuf = AutoInit; //The autoinit setting to use!
		SB_LOGCOMMAND
		if (AutoInit)
		{
			SOUNDBLASTER.wordparamoutput = SOUNDBLASTER.AutoInitBlockSize; //Start this transfer now!
			DSP_startDMADAC(1,0); //Start DMA transfer!
		}
		break;
	case 0x1F: //Auto-Initialize DMA DAC, 2-bit ADPCM reference(DSP 2.01+)
		SB2COMMAND
		AutoInit = 1; //Auto initialize command instead!
	case 0x17: //DMA DAC, 2-bit ADPCM reference
		ADPCM_reference = 1; //We're using the reference byte in the transfer!
	case 0x16: //DMA DAC, 2-bit ADPCM
		SB_LOGCOMMAND
		DSP_startParameterADPCM(command,ADPCM_FORMAT_2BIT,ADPCM_reference,AutoInit); //Starting the ADPCM command!
		break;
	case 0x20: //Direct ADC, 8-bit
		SB_LOGCOMMAND
		fifobuffer_clear(SOUNDBLASTER.DSPindata); //Wait for input!
		writefifobuffer(SOUNDBLASTER.DSPindata, SOUNDBLASTER.recordedsample); //Give the current sample!											fifobuffer_gotolast(SOUNDBLASTER.DSPindata); //Give the result!
		SOUNDBLASTER.command = SOUNDBLASTER.DREQ = 0; //Finished! Stop DMA!
		break;
	case 0x2C: //Auto-initialize DMA ADC, 8-bit(DSP 2.01+)
		SB2COMMAND
		AutoInit = 1; //Auto initialize command instead!
	case 0x24: //DMA ADC, 8-bit
		SB_LOGCOMMAND
		SOUNDBLASTER.commandstep = 0; //We're at the parameter phase!
		SOUNDBLASTER.command = (int)command; //Starting this command!
		SOUNDBLASTER.DREQ = 0; //Disable DMA!
		SOUNDBLASTER.dataleft = 0; //counter of parameters!
		SOUNDBLASTER.AutoInitBuf = AutoInit; //The autoinit setting to use!
		if (AutoInit)
		{
			SOUNDBLASTER.wordparamoutput = SOUNDBLASTER.AutoInitBlockSize; //Start this transfer now!
			DSP_startDMADAC(1,1); //Start DMA transfer!
		}
		break;
	case 0x30: //MIDI read poll
	case 0x31: //MIDI read interrupt
		//Not supported on this chip?
		SB_LOGCOMMAND
		break;
	case 0x34: //MIDI read poll + write poll (UART, DSP 2.01+)
	case 0x35: //MIDI read interrupt + write poll (UART, DSP 2.01+)
	case 0x37: //MIDI read timestamp interrupt + write poll (UART, DSP 2.01+)
		SB2COMMAND
		//TODO
		SB_LOGCOMMAND
		break;
	case 0x38: //MIDI write poll
		SB_LOGCOMMAND
		SOUNDBLASTER.command = 0x38; //Start the parameter phase!
		break;
	case 0x40: //Set Time Constant
		SB_LOGCOMMAND
		SOUNDBLASTER.command = 0x40; //Set the time constant!
		break;
	case 0x48: //Set DMA Block size(DSP 2.01+)
		SB2COMMAND
		SB_LOGCOMMAND
		SOUNDBLASTER.commandstep = 0; //We're at the parameter phase!
		SOUNDBLASTER.command = (int)command; //Starting this command!
		SOUNDBLASTER.DREQ = 0; //Disable DMA!
		SOUNDBLASTER.dataleft = 0; //counter of parameters!
		break;
	case 0x7D: //Auto-initialize DMA DAC, 4-bit ADPCM Reference(DSP 2.01+)
		SB2COMMAND
		AutoInit = 1; //Auto-initialize command instead!
	case 0x75: //DMA DAC, 4-bit ADPCM Reference
		ADPCM_reference = 1; //We're using the reference byte in the transfer!
	case 0x74: //DMA DAC, 4-bit ADPCM
		SB_LOGCOMMAND
		DSP_startParameterADPCM(command,ADPCM_FORMAT_4BIT,ADPCM_reference,AutoInit); //Starting the ADPCM command!
		if (AutoInit)
		{
			SOUNDBLASTER.wordparamoutput = SOUNDBLASTER.AutoInitBlockSize; //Start this transfer now!
			DSP_startDMADAC(1,0); //Start DMA transfer!
		}
		break;
	case 0x7F: //Auto-initialize DMA DAC, 2.6-bit ADPCM Reference
		SB2COMMAND
		AutoInit = 1; //Auto-initialize command instead!
	case 0x77: //DMA DAC, 2.6-bit ADPCM Reference
		ADPCM_reference = 1; //We're using the reference byte in the transfer!
	case 0x76: //DMA DAC, 2.6-bit ADPCM
		SB_LOGCOMMAND
		DSP_startParameterADPCM(command,ADPCM_FORMAT_26BIT,ADPCM_reference,AutoInit); //Starting the ADPCM command!
		if (AutoInit)
		{
			SOUNDBLASTER.wordparamoutput = SOUNDBLASTER.AutoInitBlockSize; //Start this transfer now!
			DSP_startDMADAC(1,0); //Start DMA transfer!
		}
		break;
	case 0x80: //Silence DAC
		SB_LOGCOMMAND
		SOUNDBLASTER.command = 0x80; //Start the command!
		SOUNDBLASTER.commandstep = 0; //Reset the output step!
		break;
	case 0xD0: //Halt DMA operation, 8-bit
		SB_LOGCOMMAND
		if (SOUNDBLASTER.DREQ) //DMA enabled? Busy transaction!
		{
			SOUNDBLASTER.DMADisabled = 1; //We're a paused DMA transaction now!
		}
		break;
	case 0xD1: //Enable Speaker
		SB_LOGCOMMAND
		SOUNDBLASTER.muted = 0; //Not muted anymore!
		break;
	case 0xD3: //Disable Speaker
		SB_LOGCOMMAND
		SOUNDBLASTER.muted = 1; //Muted!
		SOUNDBLASTER.singen = 0; //Disable the sine wave generator!
		break;
	case 0xD4: //Continue DMA operation, 8-bit
		SB_LOGCOMMAND
		if (SOUNDBLASTER.DMADisabled) //DMA enabled? Busy transaction!
		{
			SOUNDBLASTER.DMADisabled = 0; //We're a continuing DMA transaction now!
		}
		break;
	case 0xD8: //Speaker Status
		SB_LOGCOMMAND
		writefifobuffer(SOUNDBLASTER.DSPindata, SOUNDBLASTER.muted ? 0x00 : 0xFF); //Give the correct status!
		fifobuffer_gotolast(SOUNDBLASTER.DSPindata); //Give the output!
		break;
	case 0xDA: //Exit Auto-initialize DMA operation, 8-bit(DSP 2.01+)
		SB2COMMAND
		SB_LOGCOMMAND
		SOUNDBLASTER.AutoInit = 0; //Disable the auto-initialize option when we're finished rendering!
		break;
	case 0xE0: //DSP Identification. Should be 2.0+, but apparently 1.5 has it too according to it's SBFMDRV driver?
		SB_LOGCOMMAND
		SOUNDBLASTER.command = 0xE0; //Start the data phase!
		break;
	case 0xE1: //DSP version
		SB_LOGCOMMAND
		writefifobuffer(SOUNDBLASTER.DSPindata, (SB_VERSION>>8)); //Give the correct version!
		fifobuffer_gotolast(SOUNDBLASTER.DSPindata); //Give the output!
		writefifobuffer(SOUNDBLASTER.DSPindata, (SB_VERSION&0xFF)); //Give the correct version!
		break;
	case 0xE4: //Write Test register(DSP 2.01+)
		SB2COMMAND
		SB_LOGCOMMAND
		SOUNDBLASTER.command = 0xE4; //Start the parameter phase!
		SOUNDBLASTER.commandstep = 0; //Starting the parameter phase!
		break;
	case 0xE8: //Read Test register(DSP 2.01+)
		SB2COMMAND
		SB_LOGCOMMAND
		writefifobuffer(SOUNDBLASTER.DSPindata,SOUNDBLASTER.TestRegister); //Give the test register
		break;
	case 0xF0: //Sine Generator
		//Generate 2kHz signal!
		SB_LOGCOMMAND
		SOUNDBLASTER.muted = 0; //Not muted, give the diagnostic signal until muted!
		SOUNDBLASTER.singen = 1; //Enable the sine wave generator!
		SOUNDBLASTER.singentime = 0.0f; //Reset time on the sine wave generator!
		break;
	case 0xF2: //IRQ Request, 8-bit
		SB_LOGCOMMAND
		#ifdef IS_LONGDOUBLE
		soundblaster_IRR = 10000.0L; //IRQ request in 10us, according to Dosbox!
		#else
		soundblaster_IRR = 10000.0; //IRQ request in 10us, according to Dosbox!
		#endif
		break;
	case 0xF8: //Undocumented command according to Dosbox
		SB_LOGCOMMAND
		writefifobuffer(SOUNDBLASTER.DSPindata,0x00); //Give zero bytes!
		fifobuffer_gotolast(SOUNDBLASTER.DSPindata); //Use the given result!
		break;
	default: //Unknown command?
		SB_LOGINVCOMMAND
		break;
	}
}

//ADPCM decoder from Dosbox
OPTINLINE byte decode_ADPCM_4_sample(byte sample, byte *reference, int_32 *scale)
{
	static const sbyte scaleMap[64] = {
		0,  1,  2,  3,  4,  5,  6,  7,  0,  -1,  -2,  -3,  -4,  -5,  -6,  -7,
		1,  3,  5,  7,  9, 11, 13, 15, -1,  -3,  -5,  -7,  -9, -11, -13, -15,
		2,  6, 10, 14, 18, 22, 26, 30, -2,  -6, -10, -14, -18, -22, -26, -30,
		4, 12, 20, 28, 36, 44, 52, 60, -4, -12, -20, -28, -36, -44, -52, -60
	};
	static const byte adjustMap[64] = {
		0, 0, 0, 0, 0, 16, 16, 16,
		0, 0, 0, 0, 0, 16, 16, 16,
		240, 0, 0, 0, 0, 16, 16, 16,
		240, 0, 0, 0, 0, 16, 16, 16,
		240, 0, 0, 0, 0, 16, 16, 16,
		240, 0, 0, 0, 0, 16, 16, 16,
		240, 0, 0, 0, 0,  0,  0,  0,
		240, 0, 0, 0, 0,  0,  0,  0
	};

	int_32 samp = sample + *scale;

	if ((samp < 0) || (samp > 63)) {
		//LOG(LOG_SB, LOG_ERROR)("Bad ADPCM-4 sample");
		if (samp < 0) samp = 0;
		if (samp > 63) samp = 63;
	}

	int_32 ref = *reference + scaleMap[samp];
	if (ref > 0xff) *reference = 0xff;
	else if (ref < 0x00) *reference = 0x00;
	else *reference = (byte)(ref & 0xff);
	*scale = (*scale + adjustMap[samp]) & 0xff;

	return (byte)*reference;
}

OPTINLINE byte decode_ADPCM_2_sample(byte sample, byte *reference, int_32 *scale)
{
	static const sbyte scaleMap[24] = {
		0,  1,  0,  -1, 1,  3,  -1,  -3,
		2,  6, -2,  -6, 4, 12,  -4, -12,
		8, 24, -8, -24, 6, 48, -16, -48
	};
	static const byte adjustMap[24] = {
		0, 4,   0, 4,
		252, 4, 252, 4, 252, 4, 252, 4,
		252, 4, 252, 4, 252, 4, 252, 4,
		252, 0, 252, 0
	};

	int_32 samp = sample + *scale;
	if ((samp < 0) || (samp > 23)) {
		//LOG(LOG_SB, LOG_ERROR)("Bad ADPCM-2 sample");
		if (samp < 0) samp = 0;
		if (samp > 23) samp = 23;
	}

	int_32 ref = *reference + scaleMap[samp];
	if (ref > 0xff) *reference = 0xff;
	else if (ref < 0x00) *reference = 0x00;
	else *reference = (byte)(ref & 0xff);
	*scale = (*scale + adjustMap[samp]) & 0xff;

	return (byte)*reference;
}

OPTINLINE byte decode_ADPCM_3_sample(byte sample, byte *reference,int_32 *scale)
{
	static const sbyte scaleMap[40] = {
		0,  1,  2,  3,  0,  -1,  -2,  -3,
		1,  3,  5,  7, -1,  -3,  -5,  -7,
		2,  6, 10, 14, -2,  -6, -10, -14,
		4, 12, 20, 28, -4, -12, -20, -28,
		5, 15, 25, 35, -5, -15, -25, -35
	};
	static const byte adjustMap[40] = {
		0, 0, 0, 8,   0, 0, 0, 8,
		248, 0, 0, 8, 248, 0, 0, 8,
		248, 0, 0, 8, 248, 0, 0, 8,
		248, 0, 0, 8, 248, 0, 0, 8,
		248, 0, 0, 0, 248, 0, 0, 0
	};

	int_32 samp = sample + *scale;
	if ((samp < 0) || (samp > 39)) {
		//LOG(LOG_SB, LOG_ERROR)("Bad ADPCM-3 sample");
		if (samp < 0) samp = 0;
		if (samp > 39) samp = 39;
	}

	int_32 ref = *reference + scaleMap[samp];
	if (ref > 0xff) *reference = 0xff;
	else if (ref < 0x00) *reference = 0x00;
	else *reference = (byte)(ref & 0xff);
	*scale = (*scale + adjustMap[samp]) & 0xff;

	return (byte)*reference;
}

OPTINLINE void DSP_writeData(byte data, byte isDMA)
{
	switch (SOUNDBLASTER.command) //What command?
	{
	case 0: return; //Unknown command!
	case 0x10: //Direct DAC output?
		sb_leftsample = sb_rightsample = data; //Set the direct DAC output!
		SOUNDBLASTER.DMADisabled = 0; //Disable DMA transaction!
		SOUNDBLASTER.DREQ = 0; //Lower DREQ!
		SOUNDBLASTER.command = 0; //No command anymore!
		fifobuffer_clear(SOUNDBLASTER.DSPoutdata); //Clear the output buffer to use this sample!
		break;
	case 0x40: //Set Time Constant?
		//timer rate: 1000000000.0 / __SOUNDBLASTER_SAMPLERATE
		//TimeConstant = 256 - (1000000(us) / (SampleChannels * SampleRate)), where SampleChannels is 1 for non-SBPro.
		#ifdef IS_LONGDOUBLE
		SOUNDBLASTER.frequency = (1000000.0L / (DOUBLE)(256 - data)); //Calculate the frequency to run at!
		soundblaster_sampletick = 1000000000.0L/SOUNDBLASTER.frequency; //Tick at the sample rate!
		#else
		SOUNDBLASTER.frequency = (1000000.0 / (DOUBLE)(256 - data)); //Calculate the frequency to run at!
		soundblaster_sampletick = 1000000000.0/SOUNDBLASTER.frequency; //Tick at the sample rate!
		#endif
		SOUNDBLASTER.command = 0; //No command anymore!
		break;
	case 0x14: //DMA DAC, 8-bit
	case 0x16: //DMA DAC, 2-bit ADPCM
	case 0x17: //DMA DAC, 2-bit ADPCM reference
	case 0x1C: //Auto-initialize DMA DAC, 8-bit
	case 0x1F: //Auto-initialize DMA DAC, 2-bit ADPCM Reference
	case 0x74: //DMA DAC, 4-bit ADPCM
	case 0x75: //DMA DAC, 4-bit ADPCM Reference
	case 0x76: //DMA DAC, 2.6-bit ADPCM
	case 0x77: //DMA DAC, 2.6-bit ADPCM Reference
	case 0x7D: //Auto-initialize DMA DAC, 4-bit ADPCM Reference
	case 0x7F: //Auto-initialize DMA DAC, 2.6-bit ADPCM Reference
		if (SOUNDBLASTER.commandstep) //DMA transfer active?
		{
			if (isDMA) //Must be DMA transfer!
			{
				if (SOUNDBLASTER.ADPCM_format) //Format specified? Use ADPCM!
				{
					if (SOUNDBLASTER.ADPCM_reference) //We're the reference byte?
					{
						SOUNDBLASTER.ADPCM_reference = 0; //No reference anymore!
						SOUNDBLASTER.ADPCM_currentreference = data;
						SOUNDBLASTER.ADPCM_stepsize = MIN_ADAPTIVE_STEP_SIZE; //Initialise the step size!
						writefifobuffer(SOUNDBLASTER.DSPoutdata, data); //Send the current sample for rendering!
					}
					else //Data based on the reference?
					{
						switch (SOUNDBLASTER.ADPCM_format) //What format?
						{
						case ADPCM_FORMAT_2BIT: //Dosbox DSP_DMA_2
							writefifobuffer(SOUNDBLASTER.DSPoutdata, decode_ADPCM_2_sample((data >> 6) & 0x3, &SOUNDBLASTER.ADPCM_currentreference, &SOUNDBLASTER.ADPCM_stepsize)); //Send the partial sample for rendering!
							writefifobuffer(SOUNDBLASTER.DSPoutdata, decode_ADPCM_2_sample((data >> 4) & 0x3, &SOUNDBLASTER.ADPCM_currentreference, &SOUNDBLASTER.ADPCM_stepsize)); //Send the partial sample for rendering!
							writefifobuffer(SOUNDBLASTER.DSPoutdata, decode_ADPCM_2_sample((data >> 2) & 0x3, &SOUNDBLASTER.ADPCM_currentreference, &SOUNDBLASTER.ADPCM_stepsize)); //Send the partial sample for rendering!
							writefifobuffer(SOUNDBLASTER.DSPoutdata, decode_ADPCM_2_sample((data >> 0) & 0x3, &SOUNDBLASTER.ADPCM_currentreference, &SOUNDBLASTER.ADPCM_stepsize)); //Send the partial sample for rendering!
							break;
						case ADPCM_FORMAT_26BIT: //Dosbox DSP_DMA_3
							writefifobuffer(SOUNDBLASTER.DSPoutdata, decode_ADPCM_3_sample((data >> 5)  &  0x7, &SOUNDBLASTER.ADPCM_currentreference, &SOUNDBLASTER.ADPCM_stepsize)); //Send the partial sample for rendering!
							writefifobuffer(SOUNDBLASTER.DSPoutdata, decode_ADPCM_3_sample((data >> 2)  &  0x7, &SOUNDBLASTER.ADPCM_currentreference, &SOUNDBLASTER.ADPCM_stepsize)); //Send the partial sample for rendering!
							writefifobuffer(SOUNDBLASTER.DSPoutdata, decode_ADPCM_3_sample((data &  3)  << 0x1, &SOUNDBLASTER.ADPCM_currentreference, &SOUNDBLASTER.ADPCM_stepsize)); //Send the partial sample for rendering!
							break;
						case ADPCM_FORMAT_4BIT: //Dosbox DSP_DMA_4
							writefifobuffer(SOUNDBLASTER.DSPoutdata, decode_ADPCM_4_sample((data >> 4) & 0xF, &SOUNDBLASTER.ADPCM_currentreference, &SOUNDBLASTER.ADPCM_stepsize)); //Send the partial sample for rendering!
							writefifobuffer(SOUNDBLASTER.DSPoutdata, decode_ADPCM_4_sample(data        & 0xF, &SOUNDBLASTER.ADPCM_currentreference, &SOUNDBLASTER.ADPCM_stepsize)); //Send the partial sample for rendering!
							break;
						default: //Unknown format?
							//Ignore output!
							writefifobuffer(SOUNDBLASTER.DSPoutdata, 0x80); //Send the empty sample for rendering!
							break;
						}
					}
				}
				else //Normal 8-bit sample?
				{
					writefifobuffer(SOUNDBLASTER.DSPoutdata, data); //Send the current sample for rendering!
				}
				if (SOUNDBLASTER.dataleft==0) //Nothing left?
				{
					goto nooutdataleft;
				}
				if (--SOUNDBLASTER.dataleft==0) //One data used! Finished? Give IRQ!
				{
					nooutdataleft: //Nothing left?
					SoundBlaster_IRQ8(); //Raise the 8-bit IRQ!
					if (SOUNDBLASTER.AutoInit) //Autoinit enabled?
					{
						SoundBlaster_DetectDMALength((byte)SOUNDBLASTER.command, SOUNDBLASTER.AutoInitBlockSize); //Reload the length of the DMA transfer to play back, in bytes!
						SOUNDBLASTER.DREQ |= (2|8); //Wait for the next sample to be played, according to the sample rate! Also wait for the IRQ to be aclowledged!
					}
					else
					{
						SOUNDBLASTER.DREQ = 0; //Stop DMA: we're finished!
					}
				}
				else
				{
					SOUNDBLASTER.DREQ |= 2; //Wait for the next sample to be played, according to the sample rate!
				}
			}
			else //Manual override?
			{
				DSP_writeCommand(data); //Override to command instead!
			}
		}
		else //Parameter phase?
		{
			switch (SOUNDBLASTER.dataleft++) //What step?
			{
			case 0: //Length lo byte!
				SOUNDBLASTER.wordparamoutput = (word)data; //The first parameter!
				break;
			case 1: //Length hi byte!
				SOUNDBLASTER.wordparamoutput |= (((word)data)<<8); //The second parameter!
				DSP_startDMADAC(SOUNDBLASTER.AutoInitBuf,0); //Start the DMA DAC!
				break;
			}
		}
		break;
	case 0x2C: //Auto-Initialize DMA ADC, 8-bit
	case 0x24: //DMA ADC, 8-bit
		if (SOUNDBLASTER.commandstep) //DMA transfer active?
		{
			if (isDMA) //Must be DMA transfer!
			{
				//Writing from DMA during recording??? Must be misconfigured! Ignore the writes!
			}
			else //Manual override?
			{
				DSP_writeCommand(data); //Override to command instead!
			}
		}
		else //Parameter phase?
		{
			switch (SOUNDBLASTER.dataleft++) //What step?
			{
			case 0: //Length lo byte!
				SOUNDBLASTER.wordparamoutput = (word)data; //The first parameter!
				break;
			case 1: //Length hi byte!
				SOUNDBLASTER.wordparamoutput |= (((word)data) << 8); //The second parameter!
				SoundBlaster_DetectDMALength((byte)SOUNDBLASTER.command,SOUNDBLASTER.wordparamoutput); //The length of the DMA transfer to play back, in bytes!
				SOUNDBLASTER.commandstep = 1; //Goto step 1!
				//Sound Blasters prior to SB16 return the first sample in Direct Mode!
				if (SOUNDBLASTER.command==0x24) //Special DMA/Direct mode bug: first sample becomes Direct instead of DMA!
				{
					SOUNDBLASTER.DirectADC = 1; //Handle this special case instead by starting with Direct ADC input on older Sound Blasters(<SB16)!
					SoundBlaster_IRQ8(); //Raise the IRQ to identify the input!
				}
				else //Start DMA normally!
				{
					DSP_startDMADAC(SOUNDBLASTER.AutoInitBuf,1); //Start DMA DAC, autoinit supplied!
				}
				break;
			}
		}
		break;
	case 0x80: //Silence DAC?
		SOUNDBLASTER.DREQ = 0; //Lower DREQ!
		switch (SOUNDBLASTER.commandstep++)
		{
		case 0: //Length lo byte?
			SOUNDBLASTER.wordparamoutput = data; //Set the data (low byte)
			break;
		case 1: //Length hi byte?
			SOUNDBLASTER.wordparamoutput |= ((word)data<<8); //Set the samples to be silent!
			SOUNDBLASTER.silencesamples = SOUNDBLASTER.wordparamoutput; //How many samples to be silent!
			SOUNDBLASTER.commandstep = 2; //Stuck here!
			break;
		}
		break;
	case 0xE0: //DSP Identification. Should be 2.0+, but apparently 1.5 has it too?
		SOUNDBLASTER.command = 0; //Finished!
		writefifobuffer(SOUNDBLASTER.DSPindata,~data); //Give the identification as the result!
		fifobuffer_gotolast(SOUNDBLASTER.DSPindata); //Give the result!
		break;
	case 0x38: //MIDI write poll
		SOUNDBLASTER.command = 0; //Finished!
		/*
		if (MPU_ready) //Is the MPU installed?
		{
			MIDI_OUT(data); //Write the data to the MIDI device directly (UART mode forced)!
		}
		*/
		break;
	case 0x48: //Set DMA Block size(DSP 2.01+)
		if (isDMA) return; //Not for DMA transfers!
		switch (SOUNDBLASTER.dataleft++) //What step?
		{
		case 0: //Length lo byte!
			SOUNDBLASTER.wordparamoutput = (word)data; //The first parameter!
			break;
		case 1: //Length hi byte!
			SOUNDBLASTER.wordparamoutput |= (((word)data) << 8); //The second parameter!
			SOUNDBLASTER.AutoInitBlockSize = SOUNDBLASTER.wordparamoutput; //The length of the Auto-Init DMA transfer to play back, in bytes!
			SOUNDBLASTER.command = 0; //Finished!
			break;
		}
		break;
	case 0xE4: //Write Test register(DSP 2.01+)
		SOUNDBLASTER.TestRegister = data; //Write to the test register!
		SOUNDBLASTER.command = 0; //Finished!
		break;
	default: //Unknown command?
		//Ignore command!
		break; //Simply ignore anything sent!
	}
}

byte lastresult = 0x00; //Keep the last result in the buffer when nothing is to be read(Required for some Jangle DEMO according to Dosbox)!

OPTINLINE void DSP_writeDataCommand(byte value)
{
	if (SOUNDBLASTER.command != 0) //Handling data?
	{
		DSP_writeData(value,0); //Writing data!
	}
	else //Writing a command?
	{
		DSP_writeCommand(value); //Writing command!
	}
}

OPTINLINE byte readDSPData(byte isDMA)
{
	switch (SOUNDBLASTER.command) //What command?
	{
	case 0x2C: //Auto-Initialize DMA ADC, 8-bit
	case 0x24: //DMA ADC, 8-bit
		if (SOUNDBLASTER.commandstep) //DMA transfer active?
		{
			if (isDMA || SOUNDBLASTER.DirectADC) //Must be DMA transfer or Direct ADC single sample!
			{
				if (SOUNDBLASTER.DirectADC) //Special Direct ADC case starts DMA after?
				{
					SOUNDBLASTER.DirectADC = 0; //Clear the Direct ADC flag: we're handled!

					#ifndef RECORD_TESTWAVE
					SOUNDBLASTER.DREQ = (1|0x10|2); //Raise: we're outputting data for playback! Raise real-time flag as well!
					#else
					SOUNDBLASTER.DREQ = (1|2); //Same as above, but not realtime.
					#endif
					if (SOUNDBLASTER.DMADisabled == 1) //DMA Disabled?
					{
						SOUNDBLASTER.DMADisabled = 0; //Start the DMA transfer fully itself!
					}
				}
				if (SOUNDBLASTER.dataleft==0) goto noreaddataleft;
				if (--SOUNDBLASTER.dataleft == 0) //One data used! Finished? Give IRQ!
				{
					noreaddataleft:
					SoundBlaster_IRQ8(); //Raise the 8-bit IRQ!
					if (SOUNDBLASTER.AutoInit) //Autoinit enabled?
					{
						SoundBlaster_DetectDMALength((byte)SOUNDBLASTER.command, SOUNDBLASTER.AutoInitBlockSize); //Reload the length of the DMA transfer to play back, in bytes!
						SOUNDBLASTER.DREQ |= (2|8); //Wait for the next sample to be played, according to the sample rate! Also wait for the IRQ to be aclowledged!
					}
					else
					{
						SOUNDBLASTER.DREQ = 0; //Finished!
					}
				}
				else //Busy transfer?
				{
					SOUNDBLASTER.DREQ |= 2; //Wait for the next sample to be played, according to the sample rate!
				}
				return SOUNDBLASTER.recordedsample; //Send the current sample from DMA!
			}
			else //Non-DMA read?
			{
				return lastresult; //Give the last result, ignore the read buffer(as it's used by DMA)!
			}
		}
		break;
	default: //Unknown command?
		break; //Simply ignore anything sent!
	}

	readfifobuffer(SOUNDBLASTER.DSPindata, &lastresult); //Read the result, if any!
	return lastresult; //Unknown!
}

void DSP_HWreset()
{
	SOUNDBLASTER.command = 0; //No command!
	SOUNDBLASTER.busy = 0; //Busy for a little time!
	SOUNDBLASTER.silencesamples = 0; //No silenced samples!
	SOUNDBLASTER.IRQ8Pending = 0; //No IRQ pending!
	SOUNDBLASTER.singen = 0; //Disable the sine wave generator if it's running!
	SOUNDBLASTER.DREQ = 0; //Disable any DMA requests!
	SOUNDBLASTER.ADPCM_reference = 0; //No reference byte anymore!
	SOUNDBLASTER.ADPCM_currentreference = 0; //Reset the reference!
	SOUNDBLASTER.DirectADC = 0; //Disable the special Direct ADC status!
	fifobuffer_clear(SOUNDBLASTER.DSPindata); //Clear the input buffer!
	fifobuffer_clear(SOUNDBLASTER.DSPoutdata); //Clear the output buffer!
	sb_leftsample = sb_rightsample = 0x80; //Silence output!
}

void DSP_reset(byte data)
{
	if ((data&1) && (SOUNDBLASTER.reset!=DSP_S_RESET)) //Reset turned on?
	{
		DSP_HWreset();
		SOUNDBLASTER.reset = DSP_S_RESET; //We're reset!
	}
	else if (((data & 1) == 0) && (SOUNDBLASTER.reset == DSP_S_RESET)) //reset off?
	{
		SOUNDBLASTER.reset = DSP_S_RESET_WAIT; //Waiting for the reset to complete!
		#ifdef IS_LONGDOUBLE
		soundblaster_resettiming = 20000.0L; //20us until we're timed out!
		#else
		soundblaster_resettiming = 20000.0; //20us until we're timed out!
		#endif
	}
}

byte inSoundBlaster(word port, byte *result)
{
	byte dummy;
	if ((port&~0xF)!=SOUNDBLASTER.baseaddr) return 0; //Not our base address?
	switch (port & 0xF) //What port?
	{
	case 0x8: //FM Music - Compatible Status port
		*result = readadlibstatus(); //Read the adlib status!
		return 1; //Handled!
		break;
	case 0xA: //DSP - Read data
		*result = readDSPData(0); //Check if there's anything to read, ignore the result!
		return 1; //Handled!
		break;
	case 0xC: //DSP - Write Buffer Status
		if (SOUNDBLASTER.reset==DSP_S_NORMAL) //Not reset pending?
		{
			++SOUNDBLASTER.busy; //Increase busy time!
			*result = (SOUNDBLASTER.busy&8)?0xFF:0x7F; //Are we ready to write data? 0x80=Not ready to write. Reversed according to Dosbox(~)!
		}
		else
		{
			*result = 0xFF; //According to Dosbox!
		}
		return 1; //Handled!
	case 0xE: //DSP - Data Available Status, DSP - IRQ Acknowledge, 8-bit
		*result = ((peekfifobuffer(SOUNDBLASTER.DSPindata,&dummy)|SOUNDBLASTER.DirectADC)<<7)|0x7F; //Do we have data available? Also check for the Direct DMA on older Sound Blasters!
		if (SOUNDBLASTER.IRQ8Pending==3) //Pending and acnowledged?
		{
			SOUNDBLASTER.IRQ8Pending = 0; //Not pending anymore!
			lowerirq(__SOUNDBLASTER_IRQ8); //Lower the IRQ!
			acnowledgeIRQrequest(__SOUNDBLASTER_IRQ8); //Acnowledge!
			SOUNDBLASTER.DREQ &= ~8; //IRQ has been acnowledged, resume playback!
		}
		return 1; //We have a result!
	default:
		break;
	}
	return 0; //Not supported yet!
}

byte outSoundBlaster(word port, byte value)
{
	if ((port&~0xF) != SOUNDBLASTER.baseaddr) return 0; //Not our base address?
	switch (port & 0xF) //What port?
	{
	case 0x6: //DSP - Reset?
		DSP_reset(value); //Reset with this value!
		return 1; //Handled!
		break;
	case 0x8: //FM Music - Compatible Register port
		writeadlibaddr(value); //Write to the address port!
		return 1; //Handled!
		break;
	case 0x9: //FM Music - Compatible Data register
		writeadlibdata(value); //Write to the data port!
		return 1; //Handled!
	case 0xC: //DSP - Write Data or Command
		DSP_writeDataCommand(value); //Write data or command!
		return 1; //Handled!
	default:
		break;
	}
	return 0; //Not supported yet!
}

void StartPendingSoundBlasterIRQ(byte IRQ)
{
	if (SOUNDBLASTER.IRQ8Pending&2) //Actually pending?
	{
		SOUNDBLASTER.IRQ8Pending |= 1; //We're starting to execute our IRQ, which has been acnowledged!
	}
}

byte SoundBlaster_readDMA8()
{
	return readDSPData(1); //Gotten anything from DMA in the input buffer?
}

void SoundBlaster_writeDMA8(byte data)
{
	DSP_writeData(data,1); //Write the Data, DMA style!
}

void SoundBlaster_DREQ()
{
	DMA_SetDREQ(__SOUNDBLASTER_DMA8,((SOUNDBLASTER.DREQ&(~0x10))==1) && (SOUNDBLASTER.DMADisabled==0)); //Set the DREQ signal accordingly! Ignore bit 4 of DREQ: this is only for timing purposes!
}

void SoundBlaster_DACK()
{
	//We're transferring something?
	SOUNDBLASTER.DREQ |= 4; //We're acnowledged, inhabit more transfers until we're done(by timer)!
	SoundBlaster_DREQ(); //Set the DREQ signal accordingly!
}

void SoundBlaster_TC()
{
	//We're finished?
}

void initSoundBlaster(word baseaddr, byte version)
{
	SOUNDBLASTER.baseaddr = 0; //Default: no sound blaster emulation!
	if ((SOUNDBLASTER.DSPindata = allocfifobuffer(__SOUNDBLASTER_DSPINDATASIZE,0))!=NULL) //DSP read data buffer!
	{
		if ((SOUNDBLASTER.DSPoutdata = allocfifobuffer(__SOUNDBLASTER_DSPOUTDATASIZE,0))!=NULL) //DSP write data buffer!
		{
			if (allocDoubleBufferedSound16(__SOUNDBLASTER_SAMPLEBUFFERSIZE, &SOUNDBLASTER.soundbuffer, 0,__SOUNDBLASTER_SAMPLERATE)) //Valid buffer?
			{
				if (!addchannel(&SoundBlaster_soundGenerator, &SOUNDBLASTER.soundbuffer, "SoundBlaster", (float)__SOUNDBLASTER_SAMPLERATE, __SOUNDBLASTER_SAMPLEBUFFERSIZE, 0, SMPL8U)) //Start the sound emulation (mono) with automatic samples buffer?
				{
					dolog("adlib", "Error registering sound channel for output!");
				}
				else
				{
					setVolume(&SoundBlaster_soundGenerator, NULL, SOUNDBLASTER_VOLUME);
					SOUNDBLASTER.baseaddr = baseaddr; //The base address to use!
				}
			}
			else
			{
				dolog("adlib", "Error registering double buffer for output!");
			}
		}
	}

	initTicksHolder(&SOUNDBLASTER.recordingtimer); //Initialize the real-time recording timer!

	SOUNDBLASTER.resetport = 0xFF; //Reset the reset port!
	SOUNDBLASTER.busy = 0; //Default to not busy!
	SOUNDBLASTER.DREQ = 0; //Not requesting anything!
	SOUNDBLASTER.IRQ8Pending = 0; //Not pending anything!
	SOUNDBLASTER.muted = 1; //Default: muted!
	SOUNDBLASTER.DMADisabled = 0; //Start with enabled DMA(paused)!
	SOUNDBLASTER.command = 0; //Default: no command!
	writefifobuffer(SOUNDBLASTER.DSPindata,0xAA); //Last input!
	SOUNDBLASTER.reset = DSP_S_NORMAL; //Default state!
	lastresult = 0xAA; //Last result was 0xAA!
	sb_leftsample = sb_rightsample = 0x80; //Default to silence!

	#ifdef IS_LONGDOUBLE
	SOUNDBLASTER.frequency = (1000000.0L / (DOUBLE)(256 - 0)); //Calculate the frequency to run at!
	soundblaster_sampletick = 1000000000.0L/SOUNDBLASTER.frequency; //Tick at the sample rate!
	#else
	SOUNDBLASTER.frequency = (1000000.0 / (DOUBLE)(256 - 0)); //Calculate the frequency to run at!
	soundblaster_sampletick = 1000000000.0/SOUNDBLASTER.frequency; //Tick at the sample rate!
	#endif


	switch (version) //What version to emulate?
	{
	default:
	case 0: //DSP 1.05?
		SOUNDBLASTER.version = SB_VERSION15; //1.5 version!
		break;
	case 1: //DSP 2.01?
		SOUNDBLASTER.version = SB_VERSION20; //2.0 version!
		break;
	}

	register_PORTIN(&inSoundBlaster); //Status port (R)
	//All output!
	register_PORTOUT(&outSoundBlaster); //Address port (W)
	registerIRQ(__SOUNDBLASTER_IRQ8,&StartPendingSoundBlasterIRQ,NULL); //Pending SB IRQ only!
	registerDMA8(__SOUNDBLASTER_DMA8,&SoundBlaster_readDMA8,&SoundBlaster_writeDMA8); //DMA access of the Sound Blaster!
	registerDMATick(__SOUNDBLASTER_DMA8,&SoundBlaster_DREQ,&SoundBlaster_DACK,&SoundBlaster_TC);

	DSP_HWreset(); //Hardware reset!

	//Our tick timings!
	soundblaster_soundtiming = (uint_32)(soundblaster_recordingtiming = 0);
}

void doneSoundBlaster()
{
#ifdef LOG_RECORDING
	if (sb_output) //Recording?
	{
		closeWAV(&sb_output); //Close the file!
	}
#endif
	removechannel(&SoundBlaster_soundGenerator, NULL, 0); //Stop the sound emulation?
	freeDoubleBufferedSound(&SOUNDBLASTER.soundbuffer); //Free our double buffered sound!
	free_fifobuffer(&SOUNDBLASTER.DSPindata); //Release our input buffer!
	free_fifobuffer(&SOUNDBLASTER.DSPoutdata); //Release our output buffer!
}
