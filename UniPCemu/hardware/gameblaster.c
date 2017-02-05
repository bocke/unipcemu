#include "headers/types.h" //Basic types!
#include "headers/support/sounddoublebuffer.h" //Double buffered sound support!
#include "headers/emu/sound.h" //Sound support!
#include "headers/support/signedness.h" //Sign conversion support!
#include "headers/support/log.h" //Logging support!
#include "headers/hardware/ports.h" //I/O support!
#include "headers/support/filters.h" //Filter support!
#include "headers/support/wave.h" //WAV logging test support!

//Are we disabled?
#define __HW_DISABLED 0

//Define to log a test wave of 440Hz!
//#define TESTWAVE

//To filter the output signal before resampling?
#define FILTER_SIGNAL

//Game Blaster sample rate and other audio defines!
//Game blaster runs at 14MHz divided by 2 divided by 256 clocks to get our sample rate to play at! Or divided by 4 to get 3.57MHz!
//Divided by 4 when rendering 16-level output using PWM equals 4 times lower frequency when using levels instead of PWM(16-level PCM). So divide 4 further by 16 for the used rate!
//Reduce it by 16 times to provide 16-PWM states both positive and negative(using positive and negative signals, e.g. +5V, 0V and -5V)!
#define MHZ14_BASETICK 4
//#define MHZ14_BASETICK 256
//We render at ~44.1kHz!
#define MHZ14_RENDERTICK 324

//Base rate of the Game Blaster to run at!
#define __GAMEBLASTER_BASERATE (MHZ14/MHZ14_BASETICK) 

//Renderer defines to use!
#define __GAMEBLASTER_SAMPLERATE (MHZ14/MHZ14_RENDERTICK)
#define __GAMEBLASTER_SAMPLEBUFFERSIZE 4096
#define __GAMEBLASTER_VOLUME 100.0f

//We're two times 6 channels mixed on left and right, so not 6 channels but 12 channels each!
#define __GAMEBLASTER_AMPLIFIER (1.0/12.0)

//Log the rendered Game Blaster raw output stream?
//#define LOG_GAMEBLASTER

//Enable generation of PWM signal instead of direct signal to generate samples?
#define PWM_OUTPUT

//Set up a test wave, with special signal, when enabled?
//#define DEBUG_OUTPUT 550.0f

typedef struct
{
	byte Amplitude; //Amplitude: 0-16, to wrap around!
	byte PWMCounter; //Counter 0-16 that's counting!
	byte output; //Output signal that's saved!
	byte flipflopoutput; //Output signal of the PWM!
	int_32 result; //The resulting output of the PWM signal!
} PWMOUTPUT; //Channel PWM output signal for left or right channel!

typedef struct
{
	byte frequency;
	byte frequency_enable;
	byte noise_enable;
	byte octave; //0-7
	byte amplitude[2]; //0-F?
	byte envelope[2]; //0-F, 10=off.

	//Data required for timing the square wave
	float time; //Time
	float freq; //Frequency!
	byte level; //The level!
	byte ampenv[16]; //All envelope outputs! Index Bit0=Right channel, Bit1=Channel output index, Bit 2=Noise output! Output: 0=Negative, 1=Positive, 2=Neutral(no output)
	byte toneonnoiseonflipflop; //Flipflop used for mode 3 rendering!
	byte noisechannel; //Linked noise channel!
	byte PWMAmplitude[2]; //PWM amplitude for left and right channel to use!
	PWMOUTPUT PWMOutput[2]; //Left/right channel PWM output signal
} SAA1099_CHANNEL;

typedef struct
{
	//Data required for simulating noise generators!
	float freq; //Frequency!
	byte laststatus; //The last outputted status for detecting cycles!
	uint_32 level; //The level!
	byte levelbit; //Current bit from the current level!
} SAA1099_NOISE;

typedef struct
{
	float freq; //Currently used frequency!
	uint_32 timepoint; //Point that overflows in time!
	uint_32 timeout; //Half-wave timeout!
	byte output; //Flipflop output!
} SAA1099_SQUAREWAVE;

typedef struct
{
	//Basic storage!
	byte regsel; //The selected register!
	byte registers[0x20]; //All selectable registers!

	//Global Data!
	word noise_params[2];
	word env_enable[2];
	word env_reverse_right[2];
	byte env_mode[2];
	word env_bits[2];
	word env_clock[2];
	byte env_step[2];
	byte all_ch_enable;
	byte sync_state;
	
	//Information taken from the registers!
	SAA1099_CHANNEL channels[8]; //Our channels!
	SAA1099_NOISE noise[2]; //Noise generators!
	SAA1099_SQUAREWAVE squarewave[10]; //Everything needed to generate a square wave!
} SAA1099; //All data for one SAA-1099 chip!

struct
{
	word baseaddr; //Base address of the Game Blaster!
	byte soundblastercompatible; //Do we use sound blaster compatible I/O
	SOUNDDOUBLEBUFFER soundbuffer; //Our two sound buffers for our two chips!
	byte storelatch[2]; //Two store/latch buffers!
	SAA1099 chips[2]; //The two chips for generating output!
	HIGHLOWPASSFILTER filter[2]; //Filter for left and right channels, low-pass type!
	uint_32 baseclock; //Base clock to render at(up to bus rate of 14.31818MHz)!
} GAMEBLASTER; //Our game blaster information!

float AMPLIFIER = 0.0; //The amplifier, amplifying samples to the full range!

WAVEFILE *GAMEBLASTER_LOG = NULL; //Logging the Game Blaster output?

OPTINLINE byte SAAEnvelope(byte waveform, byte position)
{
	switch (waveform&7) //What waveform?
	{
		case 0: //Zero amplitude?
			return 0; //Always 0!
		case 1: //Maximum amplitude?
			return 0xF; //Always max!
		case 2: //Single decay?
			if (position<0x10)
				return 0xF-position; //Decay!
			else
				return 0; //Silence!
		case 3: //Repetitive decay?
			return 0xF-(position&0xF); //Repetitive decay!
		case 4: //Single triangular?
			if (position>0x20) //Zero past?
				return 0; //Zero!
			else if (position>0x10) //Decay?
				return 0xF-(position&0xF); //Decay!
			else //Attack?
				return (position&0xF); //Attack!
		case 5: //Repetitive triangular?
			if (position&0x10) //Decay?
				return 0xF-(position&0xF); //Decay!
			else //Attack?
				return (position&0xF); //Attack!
		case 6: //Single attack?
			if (position<0x10)
				return position; //Attack!
			else
				return 0;
		case 7: //Repetitive attack?
			return (position&0xF); //Attack!
	}
	return 0; //Unknown envelope?
}

OPTINLINE word calcAmplitude(byte amplitude)
{
	return (((amplitude<<15)-amplitude)>>4); //Simple calculation for our range!
}

int_32 amplitudes[0x10]; //All possible amplitudes!

byte AmpEnvPrecalcs[0x40]; //AmpEnv precalcs of all possible states!
OPTINLINE void updateAmpEnv(SAA1099 *chip, byte channel)
{
	chip->channels[channel].PWMAmplitude[0] = (((int_32)(chip->channels[channel].amplitude[0])*(int_32)chip->channels[channel].envelope[0]) >> 4)&0xF; //Left envelope PWM time!
	chip->channels[channel].PWMAmplitude[1] = (((int_32)(chip->channels[channel].amplitude[1])*(int_32)chip->channels[channel].envelope[1]) >> 4)&0xF; //Right envelope PWM time!
	//bit0=right channel
	//bit1=square wave output
	//bit2=noise output
	//bit3=PWM period
	//Generate all 16 state precalcs!
	memcpy(&chip->channels[channel].ampenv[0],&AmpEnvPrecalcs[(((chip->channels[channel].frequency_enable<<1)|chip->channels[channel].noise_enable)<<4)],(sizeof(AmpEnvPrecalcs[0])<<4)); //Copy
}

OPTINLINE void calcAmpEnvPrecalcs()
{
	word i;
	byte input;
	for (i=0;i<NUMITEMS(AmpEnvPrecalcs);++i) //Process all precalcs!
	{
		input = (i&0xF); //Input signal we're precalculating!
		//Output:
		//bit0=Right channel
		//bit1=Sign. 0=Negative, 1=Positive
		//bit2=Ignore sign. We're silence!
		//Lookup table input:
		//bits0-3=Index into the lookup table to generate!
		//bit4=Noise enable
		//bit5=Frequency enable
		switch ((i>>4)&3) //Noise/frequency mode?
		{
			default: //Safety check
			case 0: //Both disabled?
				AmpEnvPrecalcs[i] = 4; //No output, channel and positive/negative doesn't matter!
				break;
			case 1: //Noise only?
				AmpEnvPrecalcs[i] = ((input&4)>>1)|(input&1); //Noise at max volume!
				++input;
				break;
			case 2: //Frequency only?
				AmpEnvPrecalcs[i] = (input&3); //Noise at max volume!
				break;
			case 3: //Noise+Frequency?
				if (input&2) //Tone high state?
				{
					AmpEnvPrecalcs[i] = (input&1)|2; //Noise at max volume, positive!
				}
				else if ((input&4)==0) //Tone low and noise is low? Low at full amplitude!
				{
					AmpEnvPrecalcs[i] = (input&1); //Noise at max volume, negative!
				}
				else //Tone low? Then noise is high every other PWM period!
				{
					AmpEnvPrecalcs[i] = ((input&8)>>2)|(input&1); //Noise at half volume!
				}
				break;
		}
	}
}

OPTINLINE void tickSAAEnvelope(SAA1099 *chip, byte channel)
{
	static byte basechannels[2] = {0,3}; //The base channels!
	byte basechannel;
	channel &= 1; //Only two channels available!
	basechannel = basechannels[channel]; //Base channel!
	if (chip->env_enable[channel]) //Envelope enabled and running?
	{
		byte step,mode,mask; //Temp data!
		mode = chip->env_mode[channel]; //The mode to use!
		//Step form 0..63 and then loop 32..63
		step = ++chip->env_step[channel];
		step &= 0x3F; //Wrap around!
		step |= (chip->env_step[channel]&0x20); //OR in the current high block to loop the high part!
		chip->env_step[channel] = step; //Save the new step now used!
		mask = 0xF; //Full resolution!
		mask &= ~chip->env_bits[channel]; //Apply the bit resolution we use to mask bits off when needed!
		
		//Now, apply the current envelope!
		chip->channels[basechannel].envelope[0] = chip->channels[basechannel+1].envelope[0] = chip->channels[basechannel+2].envelope[0] = (SAAEnvelope(mode,step)&mask); //Apply the normal envelope!
		if (chip->env_reverse_right[channel]) //Reverse right envelope?
		{
			chip->channels[basechannel].envelope[1] = chip->channels[basechannel+1].envelope[1] = chip->channels[basechannel+2].envelope[1] = ((0xF-SAAEnvelope(mode,step))&mask); //Apply the reversed envelope!
		}
		else //Normal right envelope?
		{
			chip->channels[basechannel].envelope[1] = chip->channels[basechannel+1].envelope[1] = chip->channels[basechannel+2].envelope[1] = (SAAEnvelope(mode,step)&mask); //Apply the normal envelope!
		}
	}
	else //Envelope mode off, set all envelope factors to 16!
	{
		chip->channels[basechannel].envelope[0] = chip->channels[basechannel].envelope[1] = 
			chip->channels[basechannel+1].envelope[0] = chip->channels[basechannel+1].envelope[1] =
			chip->channels[basechannel+2].envelope[0] = chip->channels[basechannel+2].envelope[1] = 0x10; //We're off!
	}
	updateAmpEnv(chip,basechannel); //Update the amplitude/envelope!
	updateAmpEnv(chip,basechannel+1); //Update the amplitude/envelope!
	updateAmpEnv(chip,basechannel+2); //Update the amplitude/envelope!
}

OPTINLINE void writeSAA1099Address(SAA1099 *chip, byte address)
{
	chip->regsel = (address&0x1F); //Select the register!
	switch (chip->regsel) //What register has been selected?
	{
		case 0x18:
		case 0x19:
			if (chip->env_clock[0]) tickSAAEnvelope(chip,0); //Tick channel 0?
			if (chip->env_clock[1]) tickSAAEnvelope(chip,1); //Tick channel 1?
			break;
		default: //Unknown?
			break;
	}
}

OPTINLINE void updateSAA1099RNGfrequency(SAA1099 *chip, byte channel)
{
	byte channel2=channel|8;
	if (chip->noise[channel].freq!=chip->squarewave[channel2].freq) //Frequency changed?
	{
		chip->squarewave[channel2].timeout = (uint_32)(__GAMEBLASTER_BASERATE/(double)(2.0*chip->noise[channel].freq)); //New timeout!
		chip->squarewave[channel2].timepoint = 0; //Reset the timepoint!
		chip->squarewave[channel2].freq = chip->noise[channel].freq; //We're updated!
	}
}

OPTINLINE void updateSAA1099frequency(SAA1099 *chip, byte channel) //on octave/frequency change!
{
	channel &= 7; //Safety on channel!
	chip->channels[channel].freq = (float)((double)((GAMEBLASTER.baseclock/512)<<chip->channels[channel].octave)/(double)(511.0-chip->channels[channel].frequency)); //Calculate the current frequency to use!
	if (chip->channels[channel].freq!=chip->squarewave[channel].freq) //Frequency changed?
	{
		chip->squarewave[channel].timeout = (uint_32)(__GAMEBLASTER_BASERATE/(double)(2.0*chip->channels[channel].freq)); //New timeout!
		chip->squarewave[channel].timepoint = 0; //Reset!
		chip->squarewave[channel].freq = chip->channels[channel].freq; //We're updated!
	}
}

OPTINLINE void writeSAA1099Value(SAA1099 *chip, byte value)
{
	INLINEREGISTER byte reg;
	reg = chip->regsel; //The selected register to write to!
	chip->registers[reg] = value; //Save the register data itself!
	byte oldval,updated; //For detecting updates!
	word oldvalw;
	switch (reg) //What register is written?
	{
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x05: //Channel n amplitude?
			reg &= 7;
			oldvalw = chip->channels[reg].amplitude[0];
			chip->channels[reg].amplitude[0] = value&0xF;
			updated = (chip->channels[reg].amplitude[0]!=oldvalw); //Changed?

			oldvalw = chip->channels[reg].amplitude[1];
			chip->channels[reg].amplitude[1] = (value>>4);
			updated |= (chip->channels[reg].amplitude[1]!=oldvalw); //Changed?

			if (updated) updateAmpEnv(chip,reg); //Update amplitude/envelope!
			break;
		case 0x08:
		case 0x09:
		case 0x0A:
		case 0x0B:
		case 0x0C:
		case 0x0D: //Channel n frequency?
			reg &= 7;
			oldval = chip->channels[reg].frequency;
			chip->channels[reg].frequency = value; //Set the frequency!
			if (oldval!=chip->channels[reg].frequency) updateSAA1099frequency(chip,reg); //Update frequency!
			break;
		case 0x10:
		case 0x11:
		case 0x12: //Channel n octave?
			reg &= 3;
			oldval = chip->channels[reg<<1].octave;
			chip->channels[reg<<1].octave = (value&7);
			if (oldval!=chip->channels[reg<<1].octave) updateSAA1099frequency(chip,(reg<<1)); //Update frequency!
			
			oldval = chip->channels[(reg<<1)|1].octave;
			chip->channels[(reg<<1)|1].octave = ((value>>4)&7);
			if (oldval!=chip->channels[(reg<<1)|1].octave) updateSAA1099frequency(chip,((reg<<1)|1)); //Update frequency!
			break;
		case 0x14: //Channel n frequency enable?
			oldval = chip->channels[0].frequency_enable;
			chip->channels[0].frequency_enable = (value&1);
			if (oldval!=chip->channels[0].frequency_enable) updateAmpEnv(chip,0); //Update AmpEnv!

			value >>= 1;
			oldval = chip->channels[1].frequency_enable;
			chip->channels[1].frequency_enable = (value&1);
			if (oldval!=chip->channels[1].frequency_enable) updateAmpEnv(chip,1); //Update AmpEnv!

			value >>= 1;
			oldval = chip->channels[2].frequency_enable;
			chip->channels[2].frequency_enable = (value&1);
			if (oldval!=chip->channels[2].frequency_enable) updateAmpEnv(chip,2); //Update AmpEnv!

			value >>= 1;
			oldval = chip->channels[3].frequency_enable;
			chip->channels[3].frequency_enable = (value&1);
			if (oldval!=chip->channels[3].frequency_enable) updateAmpEnv(chip,3); //Update AmpEnv!

			value >>= 1;
			oldval = chip->channels[4].frequency_enable;
			chip->channels[4].frequency_enable = (value&1);
			if (oldval!=chip->channels[4].frequency_enable) updateAmpEnv(chip,4); //Update AmpEnv!

			value >>= 1;
			oldval = chip->channels[5].frequency_enable;
			chip->channels[5].frequency_enable = (value&1);
			if (oldval!=chip->channels[5].frequency_enable) updateAmpEnv(chip,5); //Update AmpEnv!
			break;
		case 0x15: //Channel n noise enable?
			reg = value; //Load for processing!
			oldval = chip->channels[0].noise_enable;
			chip->channels[0].noise_enable = (reg&1);
			if (oldval!=chip->channels[0].noise_enable) updateAmpEnv(chip,0); //Update AmpEnv!

			reg >>= 1;
			oldval = chip->channels[1].noise_enable;
			chip->channels[1].noise_enable = (reg&1);
			if (oldval!=chip->channels[1].noise_enable) updateAmpEnv(chip,1); //Update AmpEnv!

			reg >>= 1;
			oldval = chip->channels[2].noise_enable;
			chip->channels[2].noise_enable = (reg&1);
			if (oldval!=chip->channels[2].noise_enable) updateAmpEnv(chip,2); //Update AmpEnv!

			reg >>= 1;
			oldval = chip->channels[3].noise_enable;
			chip->channels[3].noise_enable = (reg&1);
			if (oldval!=chip->channels[3].noise_enable) updateAmpEnv(chip,3); //Update AmpEnv!

			reg >>= 1;
			oldval = chip->channels[4].noise_enable;
			chip->channels[4].noise_enable = (reg&1);
			if (oldval!=chip->channels[4].noise_enable) updateAmpEnv(chip,4); //Update AmpEnv!

			reg >>= 1;
			oldval = chip->channels[5].noise_enable;
			chip->channels[5].noise_enable = (reg&1);
			if (oldval!=chip->channels[5].noise_enable) updateAmpEnv(chip,5); //Update AmpEnv!
			break;
		case 0x16: //Noise generators parameters?
			chip->noise_params[0] = (value&3);
			chip->noise_params[1] = ((value>>4)&3);
			break;
		case 0x18:
		case 0x19: //Envelope generators parameters?
			reg &= 1; //What channel?
			chip->env_reverse_right[reg] = (value&1);
			chip->env_mode[reg] = ((value>>1)&7); //What mode?
			chip->env_bits[reg] = ((value&0x10)>>4);
			chip->env_clock[reg] = ((value&0x20)>>5);
			chip->env_enable[reg] = ((value&0x80)>>7);
			//Reset the envelope!
			chip->env_step[reg] = 0; //Reset the envelope!
			break;
		case 0x1C: //Channels enable and reset generators!
			chip->all_ch_enable = (value&1);
			if ((chip->sync_state = ((value&2)>>1))) //Sync & Reset generators?
			{
				for (reg=0;reg<6;++reg)
				{
					chip->channels[reg].level = 0;
					chip->squarewave[reg].timepoint = 0;
					chip->squarewave[reg].output = 0; //Reset wave output signal voltage?
				}
			}
			break;
		default: //Unknown register?
			break; //Silently ignore invalid and unimplemented writes!
	}
}

OPTINLINE byte getSAA1099SquareWave(SAA1099 *chip, byte channel)
{
	byte result;
	uint_32 timepoint;
	result = chip->squarewave[channel].output; //Save the current output to give!
	timepoint = chip->squarewave[channel].timepoint; //Next timepoint!
	++timepoint; //Next timepoint!
	if (timepoint>=chip->squarewave[channel].timeout) //Timeout? Flip-flop!
	{
		chip->squarewave[channel].output = result^2; //Flip-flop to produce a square wave! We're bit 1 of the output!
		timepoint = 0; //Reset the timepoint!
	}
	chip->squarewave[channel].timepoint = timepoint; //Save the resulting timepoint to advance the wave!
	return result; //Give the resulting square wave!
}

OPTINLINE int_32 getSAA1099PWM(SAA1099 *chip, byte channel, byte output)
{
	#ifdef PWM_OUTPUT
	static int_32 outputs[5] = {-SHRT_MAX,SHRT_MAX,0,0,0}; //Output, if any! Four positive/negative channel input entries plus 1 0V entry!
	#else
	static int_32 outputs[5] = {-1,1,0,0,0}; //Output, if any!
	#endif
	byte counter;
	PWMOUTPUT *PWM=&chip->channels[channel].PWMOutput[output&1]; //Our PWM channel to use!
	counter = PWM->PWMCounter++; //Apply the current counter!
	counter &= 0xF; //Reset every 16 pulses to generate a 16-level PWM!
	switch (counter|((output<<4)&0x10)) //What special cases to apply?
	{
	case 0: //Counter is zero?
	case 0x10: //Counter is zero?
		//Timeout? Load new information and start the next PWM sample!
		counter = ((PWM->output = output)&1); //Save the output for reference in the entire PWM output! Also save bit 1 for usage!
		//Load the new PWM timeout from the channel!
		PWM->flipflopoutput = ((output&6)>>1); //Start output, if any! We're starting high!
		PWM->PWMCounter = 0; //Reset the counter!
		PWM->Amplitude = chip->channels[channel].PWMAmplitude[counter]; //Update the amplitude to use!
		PWM->result = outputs[PWM->flipflopoutput]; //Initial output signal for PWM, precalculated!
		counter = 0; //Reset the counter again: we're restored!
		break;
	case 0xF: //Start a PWM new pulse next sample!
		chip->channels[channel].toneonnoiseonflipflop ^= 8; //Trigger the flipflop at PWM samplerate!	
		//Passthrough!
	default: //Normal case?
		output &= 1; //We're only interested in the channel from now on!
		break;
	}
	#ifdef PWM_OUTPUT
	if (((PWM->output&4)==0) && (counter>=PWM->Amplitude)) //Not zeroed always(bit2 isn't set)? We're zeroed when the PWM period is finished!
	{
		PWM->output = 4; //We're finished! Return to 0V always for the rest of the period!
		PWM->result = 0; //No output anymore!
	}
	return PWM->result; //Give the proper output as a 16-bit sample!
	#else
	return outputs[PWM->flipflopoutput]*(sword)amplitudes[PWM->amplitude]; //Give the proper output as a simple pre-defined 16-bit sample!
	#endif
}

OPTINLINE void generateSAA1099channelsample(SAA1099 *chip, byte channel, int_32 *output_l, int_32 *output_r)
{
	byte output;
	channel &= 7;
	chip->channels[channel].level = getSAA1099SquareWave(chip,channel); //Current flipflop output of the square wave generator!

	//Tick the envelopes when needed!
	if ((channel==1) && (chip->env_clock[0]==0))
		tickSAAEnvelope(chip,0);
	if ((channel==4) && (chip->env_clock[1]==0))
		tickSAAEnvelope(chip,1);

	output = chip->channels[channel].toneonnoiseonflipflop; //Tone/noise flipflop every other PWM sample!
	output |= chip->noise[chip->channels[channel].noisechannel].levelbit; //Use noise? If the noise level is high (noise 0 for channel 0-2, noise 1 for channel 3-5); Level bit 0 taken always to bit 2!
	output |= chip->channels[channel].level; //Level is always 1-bit! Level to bit 2!
	//Check and apply for noise! Substract to avoid overflows, half amplitude only
	*output_l += getSAA1099PWM(chip,channel,chip->channels[channel].ampenv[output]); //Output left!
	*output_r += getSAA1099PWM(chip,channel,chip->channels[channel].ampenv[output|1]); //Output right!
}

OPTINLINE void tickSAA1099noise(SAA1099 *chip, byte channel)
{
	byte noise_flipflop;

	channel &= 1; //Only two channels!

	//Check the current noise generators and update them!
	//Noise channel output!
	noise_flipflop = getSAA1099SquareWave(chip,channel|8); //Current flipflop output of the noise timer!
	if ((noise_flipflop ^ chip->noise[channel].laststatus)) //Half-wave switched state? We're to update the noise output!
	{
		if (((chip->noise[channel].level & 0x20000) == 0) == ((chip->noise[channel].level & 0x0400) == 0))
			chip->noise[channel].level = (chip->noise[channel].level << 1) | 1;
		else
			chip->noise[channel].level <<= 1;
		chip->noise[channel].levelbit = ((chip->noise[channel].level&1)<<2); //Current level bit has been updated, preshifted to bit 2 of the output!
	}
	chip->noise[channel].laststatus = noise_flipflop; //Save the last status!
}

float noise_frequencies[3] = {31250.0f*2.0f,15625.0f*2.0f,7812.0f*2.0f}; //Normal frequencies!

OPTINLINE void generateSAA1099sample(SAA1099 *chip, int_32 *leftsample, int_32 *rightsample) //Generate a sample on the requested chip!
{
	int_32 output_l, output_r;

	switch (chip->noise_params[0]) //What frequency to use?
	{
	default:
	case 0:
	case 1:
	case 2: //Normal frequencies!
		chip->noise[0].freq = noise_frequencies[chip->noise_params[0]]; //Normal lookup!
		break;
	case 3:
		chip->noise[0].freq = chip->channels[0].freq; //Channel 0 frequency instead!
	}
	updateSAA1099RNGfrequency(chip,0);

	switch (chip->noise_params[1]) //What frequency to use?
	{
	default:
	case 0:
	case 1:
	case 2: //Normal frequencies!
		chip->noise[1].freq = noise_frequencies[chip->noise_params[1]]; //Normal lookup!
		break;
	case 3:
		chip->noise[1].freq = chip->channels[3].freq; //Channel 3 frequency instead!
	}
	updateSAA1099RNGfrequency(chip,1);

	output_l = output_r = 0; //Reset the output!
	generateSAA1099channelsample(chip,0,&output_l,&output_r); //Channel 0 sample!
	generateSAA1099channelsample(chip,1,&output_l,&output_r); //Channel 1 sample!
	generateSAA1099channelsample(chip,2,&output_l,&output_r); //Channel 2 sample!
	generateSAA1099channelsample(chip,3,&output_l,&output_r); //Channel 3 sample!
	generateSAA1099channelsample(chip,4,&output_l,&output_r); //Channel 4 sample!
	generateSAA1099channelsample(chip,5,&output_l,&output_r); //Channel 5 sample!
	generateSAA1099channelsample(chip,6,&output_l,&output_r); //Channel 6 sample!

	//Finally, write the resultant samples to the result!
	tickSAA1099noise(chip,0); //Tick first noise channel!
	tickSAA1099noise(chip,1); //Tick second noise channel!

	*leftsample = output_l; //Left sample result!
	*rightsample = output_r; //Right sample result!
}

uint_32 gameblaster_soundtiming=0;
uint_32 gameblaster_rendertiming=0;

void updateGameBlaster(uint_32 MHZ14passed)
{
	int_32 leftsample[2], rightsample[2]; //Two stereo samples!
	#ifdef FILTER_SIGNAL
	static float leftsamplef[2]={0.0f,0.0f}, rightsamplef[2]={0.0f,0.0f}; //Two stereo samples, floating point format!
	#endif
	if (GAMEBLASTER.baseaddr==0) return; //No game blaster?
	//Game Blaster sound output
	gameblaster_soundtiming += MHZ14passed; //Get the amount of time passed!
	if (gameblaster_soundtiming>=MHZ14_BASETICK)
	{
		for (;gameblaster_soundtiming>=MHZ14_BASETICK;)
		{
			//Generate the sample!

			if (GAMEBLASTER.chips[0].all_ch_enable) //Sound generation of first chip?
			{
				generateSAA1099sample(&GAMEBLASTER.chips[0],&leftsample[0],&rightsample[0]); //Generate a stereo sample on this chip!
			}
			else
			{
				leftsample[0] = rightsample[0] = 0; //No sample!
			}

			if (GAMEBLASTER.chips[1].all_ch_enable) //Sound generation of first chip?
			{
				generateSAA1099sample(&GAMEBLASTER.chips[1], &leftsample[1], &rightsample[1]); //Generate a stereo sample on this chip!
			}
			else
			{
				leftsample[1] = rightsample[1] = 0; //No sample!
			}

			gameblaster_soundtiming -= MHZ14_BASETICK; //Decrease timer to get time left!

			#ifdef LOG_GAMEBLASTER
			if (GAMEBLASTER_LOG) //Logging output?
			{
				writeWAVStereoSample(GAMEBLASTER_LOG,signed2unsigned16((sword)(leftsample[0]*AMPLIFIER)),signed2unsigned16((sword)(rightsample[0]*AMPLIFIER)));
				writeWAVStereoSample(GAMEBLASTER_LOG,signed2unsigned16((sword)(leftsample[1]*AMPLIFIER)),signed2unsigned16((sword)(rightsample[1]*AMPLIFIER)));
			}
			#endif

			//Convert to floating point to apply filters&output each time!
			leftsamplef[0] = (float)leftsample[0];
			rightsamplef[0] = (float)rightsample[0];
			leftsamplef[0] += (float)leftsample[1]; //Add left channel outputs together!
			rightsamplef[0] += (float)rightsample[1]; //Add right channel outputs together!

			#ifdef FILTER_SIGNAL
			//Low-pass filters, when enabled!
			applySoundLowPassFilterObj(GAMEBLASTER.filter[0],leftsamplef[0]); //Filter low-pass left!
			applySoundLowPassFilterObj(GAMEBLASTER.filter[1],rightsamplef[0]); //Filter low-pass right!
			#endif
		}
		//Now, apply all seperate channel limits!
		leftsamplef[0] *= AMPLIFIER; //Left channel output!
		rightsamplef[0] *= AMPLIFIER; //Right channel output!
	}

	gameblaster_rendertiming += MHZ14passed; //Tick the base by our passed time!
	if (gameblaster_rendertiming>=MHZ14_RENDERTICK) //To render a sample or more samples?
	{
		for (;gameblaster_rendertiming>=MHZ14_RENDERTICK;)
		{
			//Now push the samples to the output!
			writeDoubleBufferedSound32(&GAMEBLASTER.soundbuffer,(signed2unsigned16((sword)LIMITRANGE(rightsamplef[0], SHRT_MIN, SHRT_MAX))<<16)|signed2unsigned16((sword)LIMITRANGE(leftsamplef[0], SHRT_MIN, SHRT_MAX))); //Output the sample to the renderer!
			gameblaster_rendertiming -= MHZ14_RENDERTICK; //Tick the renderer by our passed time!
		}
	}
}

byte GameBlaster_soundGenerator(void* buf, uint_32 length, byte stereo, void *userdata) //Generate a sample!
{
	uint_32 c;
	c = length; //Init c!
	
	static uint_32 last=0;
	INLINEREGISTER uint_32 buffer;

	SOUNDDOUBLEBUFFER *doublebuffer = (SOUNDDOUBLEBUFFER *)userdata; //Our double buffered sound input to use!
	int_32 mono_converter;
	sample_stereo_p data_stereo;
	sword *data_mono;
	if (stereo) //Stereo processing?
	{
		data_stereo = (sample_stereo_p)buf; //The data in correct samples!
		for (;;) //Fill it!
		{
			//Left and right samples are the same: we're a mono signal!
			readDoubleBufferedSound32(doublebuffer,&last); //Generate a stereo sample if it's available!
			buffer = last; //Load the last sample for processing!
			data_stereo->l = unsigned2signed16((word)buffer); //Load the last generated sample(left)!
			buffer >>= 16; //Shift low!
			data_stereo->r = unsigned2signed16((word)buffer); //Load the last generated sample(right)!
			++data_stereo; //Next stereo sample!
			if (!--c) return SOUNDHANDLER_RESULT_FILLED; //Next item!
		}
	}
	else //Mono processing?
	{
		data_mono = (sword *)buf; //The data in correct samples!
		for (;;) //Fill it!
		{
			//Left and right samples are the same: we're a mono signal!
			readDoubleBufferedSound32(doublebuffer,&last); //Generate a stereo sample if it's available!
			buffer = last; //Load the last sample for processing!
			mono_converter = unsigned2signed16((word)buffer); //Load the last generated sample(left)!
			buffer >>= 16; //Shift low!
			mono_converter += unsigned2signed16((word)buffer); //Load the last generated sample(right)!
			mono_converter = LIMITRANGE(mono_converter, SHRT_MIN, SHRT_MAX); //Clip our data to prevent overflow!
			*data_mono++ = mono_converter; //Save the sample and point to the next mono sample!
			if (!--c) return SOUNDHANDLER_RESULT_FILLED; //Next item!
		}
	}
}

byte outGameBlaster(word port, byte value)
{
	if (__HW_DISABLED) return 0; //We're disabled!
	if ((port&~0xF)!=GAMEBLASTER.baseaddr) return 0; //Not Game Blaster port!
	switch (port&0xF)
	{
		case 0: //Left SAA-1099?
			#ifdef LOG_GAMEBLASTER
			if (!GAMEBLASTER_LOG) GAMEBLASTER_LOG = createWAV("captures/gameblaster.wav",4,(uint_32)__GAMEBLASTER_BASERATE); //Create a wave file at our rate!
			#endif
			writeSAA1099Value(&GAMEBLASTER.chips[0],value); //Write value!
			return 1; //Handled!
		case 1: //Left SAA-1099?
			#ifdef LOG_GAMEBLASTER
			if (!GAMEBLASTER_LOG) GAMEBLASTER_LOG = createWAV("captures/gameblaster.wav",4,(uint_32)__GAMEBLASTER_BASERATE); //Create a wave file at our rate!
			#endif
			writeSAA1099Address(&GAMEBLASTER.chips[0],value); //Write address!
			return 1; //Handled!
		case 2: //Right SAA-1099?
			#ifdef LOG_GAMEBLASTER
			if (!GAMEBLASTER_LOG) GAMEBLASTER_LOG = createWAV("captures/gameblaster.wav",4,(uint_32)__GAMEBLASTER_BASERATE); //Create a wave file at our rate!
			#endif
			writeSAA1099Value(&GAMEBLASTER.chips[1],value); //Write value!
			return 1; //Handled!
		case 3: //Right SAA-1099?
			#ifdef LOG_GAMEBLASTER
			if (!GAMEBLASTER_LOG) GAMEBLASTER_LOG = createWAV("captures/gameblaster.wav",4,(uint_32)__GAMEBLASTER_BASERATE); //Create a wave file at our rate!
			#endif
			writeSAA1099Address(&GAMEBLASTER.chips[1],value); //Write address!
			return 1; //Handled!
		default: //Other addresses(16 addresses)? CT-1302!
			if (GAMEBLASTER.soundblastercompatible>1) return 0; //Ignore all other addresses!
			switch (port&0xF) //What port?
			{
				case 6: //Store 1!
				case 7: //Store 2!
					GAMEBLASTER.storelatch[port&1] = value; //Store/latch!
					return 1; //Handled!
				default:
					break;
			}
			return 0; //Not handled yet!
			break;
	}
	return 0; //Not handled!
}

byte inGameBlaster(word port, byte *result)
{
	if (__HW_DISABLED) return 0; //We're disabled!
	if ((port&~0xF)!=GAMEBLASTER.baseaddr) return 0; //Not Game Blaster port!
	switch (port&0xF)
	{
		case 0: //Left SAA-1099?
		case 1: //Left SAA-1099?
		case 2: //Right SAA-1099?
		case 3: //Right SAA-1099?
			return 0; //Not Handled! The chips cannot be read, only written!
		default: //Other addresses(16 addresses)? CT-1302!
			if (GAMEBLASTER.soundblastercompatible>1) return 0; //Ignore all other addresses!
			switch (port&0xF) //What port?
			{
				case 0x4: //Detection!
					*result = 0x7F; //Give the detection value!
					return 1; //Handled!					
				case 0xA: //Store 1!
					if (GAMEBLASTER.soundblastercompatible) return 0; //Sound blaster compatibility?
				case 0xB: //Store 2!
					*result = GAMEBLASTER.storelatch[port&1]; //Give the store/latch!
					return 1; //Handled!
				default:
					break;
			}
			return 0; //Not handled yet!
			break;
	}
}

void setGameBlaster_SoundBlaster(byte useSoundBlasterIO)
{
	if (__HW_DISABLED) return; //We're disabled!
	GAMEBLASTER.soundblastercompatible = useSoundBlasterIO?1:0; //Sound Blaster compatible I/O? Use 2 chips only with sound blaster, else full 16 ports for detection!
}

void GameBlaster_setVolume(float volume)
{
	if (__HW_DISABLED) return; //We're disabled!
	setVolume(&GameBlaster_soundGenerator,&GAMEBLASTER.soundbuffer, volume); //Set the volume!
}

void initGameBlaster(word baseaddr)
{
	uint_32 i;
	byte channel;
	if (__HW_DISABLED) return; //We're disabled!
	memset(&GAMEBLASTER,0,sizeof(GAMEBLASTER)); //Full init!
	GAMEBLASTER.baseaddr = baseaddr; //Base address of the Game Blaster!
	setGameBlaster_SoundBlaster(0); //Default to Game Blaster I/O!

	if (allocDoubleBufferedSound32(__GAMEBLASTER_SAMPLEBUFFERSIZE,&GAMEBLASTER.soundbuffer,0,__GAMEBLASTER_SAMPLERATE)) //Valid buffer?
	{
		if (!addchannel(&GameBlaster_soundGenerator,&GAMEBLASTER.soundbuffer,"GameBlaster",(float)__GAMEBLASTER_SAMPLERATE,__GAMEBLASTER_SAMPLEBUFFERSIZE,1,SMPL16S)) //Start the sound emulation (mono) with automatic samples buffer?
		{
			dolog("GameBlaster","Error registering sound channel for output!");
		}
		else
		{
			setVolume(&GameBlaster_soundGenerator,&GAMEBLASTER.soundbuffer,__GAMEBLASTER_VOLUME);
		}
	}
	else
	{
		dolog("GameBlaster","Error registering first double buffer for output!");
	}
	//dolog("adlib","sound channel added. registering ports...");
	//Ignore unregistered channel, we need to be used by software!
	register_PORTIN(&inGameBlaster); //Input ports!
	//All output!
	register_PORTOUT(&outGameBlaster); //Output ports!

	GAMEBLASTER.storelatch[0] = GAMEBLASTER.storelatch[1] = 0xFF; //Initialise our latches!

	AMPLIFIER = (float)__GAMEBLASTER_AMPLIFIER; //Set the amplifier to use!
	GAMEBLASTER.baseclock = (uint_32)(MHZ14/2); //We're currently clocking at the sample rate!
	noise_frequencies[0] = (float)((float)GAMEBLASTER.baseclock/256.0);
	noise_frequencies[1] = (float)((float)GAMEBLASTER.baseclock/512.0);
	noise_frequencies[2] = (float)((float)GAMEBLASTER.baseclock/1024.0);

	initSoundFilter(&GAMEBLASTER.filter[0],0,(float)(__GAMEBLASTER_SAMPLERATE/2.0),(float)__GAMEBLASTER_BASERATE); //Low-pass filter used left at nyquist!
	initSoundFilter(&GAMEBLASTER.filter[1],0,(float)(__GAMEBLASTER_SAMPLERATE/2.0),(float)__GAMEBLASTER_BASERATE); //Low-pass filter used right at nyquist!
	
	/*

	Test values!

	*/
#ifdef TESTWAVE
	//Load test wave information for generating samples!
	GAMEBLASTER.chips[0].squarewave[7].timeout = (uint_32)(__GAMEBLASTER_BASERATE/(double)(440.0f*2.0f)); //New timeout!
	GAMEBLASTER.chips[0].squarewave[7].timepoint = 0; //Reset!
	GAMEBLASTER.chips[0].squarewave[7].freq = 440.0f; //We're updated!

	WAVEFILE *testoutput=NULL;

	byte signal;

	testoutput = createWAV("captures/testgameblaster440hz.wav",1,(uint_32)__GAMEBLASTER_BASERATE); //Start the log!

	for (i=0;i<__GAMEBLASTER_BASERATE;++i) //Generate one second of data!
	{
		signal = getSAA1099SquareWave(&GAMEBLASTER.chips[0],7);
		writeWAVMonoSample(testoutput,signed2unsigned16(signal?(sword)32767:(sword)-32768)); //Write a sample!
	}

	closeWAV(&testoutput); //Close the wave file!
#endif
	//End test

	for (channel=0;channel<8;++channel) //Init all channels, when needed!
	{
		updateSAA1099frequency(&GAMEBLASTER.chips[0],channel); //Init frequency!
		updateSAA1099frequency(&GAMEBLASTER.chips[1],channel); //Init frequency!
		GAMEBLASTER.chips[0].channels[channel].noisechannel = (channel/3); //Our noise channel linked to this channel!
	}
	updateSAA1099RNGfrequency(&GAMEBLASTER.chips[0],0); //Init frequency!
	updateSAA1099RNGfrequency(&GAMEBLASTER.chips[1],0); //Init frequency!
	updateSAA1099RNGfrequency(&GAMEBLASTER.chips[0],1); //Init frequency!
	updateSAA1099RNGfrequency(&GAMEBLASTER.chips[1],1); //Init frequency!

	calcAmpEnvPrecalcs(); //Calculate the AmpEnv precalcs!

	gameblaster_rendertiming = gameblaster_soundtiming = 0; //Reset rendering!

	for (i=0;i<0x10;++i)
	{
		amplitudes[i] = calcAmplitude(i); //Possible amplitudes, for easy lookup!
	}

	#ifdef DEBUG_OUTPUT
	//manually set a test frequency!
	GAMEBLASTER.chips[0].squarewave[0].timeout = (uint_32)(__GAMEBLASTER_BASERATE/(double)(2.0*DEBUG_OUTPUT)); //New timeout!
	GAMEBLASTER.chips[0].squarewave[0].timepoint = 0; //Reset!
	GAMEBLASTER.chips[0].squarewave[0].freq = DEBUG_OUTPUT; //We're updated!
	outGameBlaster(GAMEBLASTER.baseaddr+1,0x00); //Channel 0 amplitude!
	outGameBlaster(GAMEBLASTER.baseaddr,0xFF); //Maximum amplitude!
	outGameBlaster(GAMEBLASTER.baseaddr+1,0x18); //Channel 0-3 settings!
	outGameBlaster(GAMEBLASTER.baseaddr,0x82); //Enable frequency output at full volume!
	outGameBlaster(GAMEBLASTER.baseaddr+1,0x1C); //General settings!
	outGameBlaster(GAMEBLASTER.baseaddr,0x01); //Enable all outputs!
	outGameBlaster(GAMEBLASTER.baseaddr+1,0x14); //Channel n frequency!
	outGameBlaster(GAMEBLASTER.baseaddr,0x01); //Enable frequency output!
	#endif
}

void doneGameBlaster()
{
	if (GAMEBLASTER_LOG) closeWAV(&GAMEBLASTER_LOG); //Close our log, if logging!
	removechannel(&GameBlaster_soundGenerator,&GAMEBLASTER.soundbuffer,0); //Stop the sound emulation?
	freeDoubleBufferedSound(&GAMEBLASTER.soundbuffer);
}
