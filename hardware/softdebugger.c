#include "headers/types.h" //Basic types!
#include "headers/hardware/ports.h" //Port support!
#include "headers/support/log.h" //Logging support!

//Are we disabled?
#define __HW_DISABLED 0

//Identifier readback!
char debugger_identifier[20] = "COMMAND:SFHB_x86EMU"; //Our identifier during standard debugger operations!
//Written back debugger data!

typedef struct
{
	//Default port support!
	char writtendata[256]; //Data written to the normal debugger!
	byte newline; //Newline status for debugger output!

	//Command support!
	byte command; //Command status! 0=None, 1,2=Command low/high, 3=Parameter.
	byte command_group; //Low command: group selection!
	byte command_execution; //High command: the command within the group!
	byte readcommand; //Read command status! 0=None, 1=Invalid command/parameter, 2=Valid command/parameter 3=Data.
	byte parameterbuffer[1024]; //A big parameter buffer for the CPU to store data in!
	word parameterpos; //Parameter position!
	word parametersize; //Parameter size!
	byte parametersack; //Parameters acknowledged?
	byte haveresult; //Do we have a result?
	byte resultbuffer[0x10000]; //A big result buffer for us to store data in!
	uint_32 resultpos; //Result position!
	uint_32 resultsize; //Result size!
	byte resultoverflow; //Overflow of reading the result by the CPU detected?
	byte identifier_pos; //Used for reading the activation string!
	struct
	{
		word outputfilename_length; //Output filename length!
		char outputfilename[0x10000]; //Output filename!
	} data; //Debugger data!
} SOFTDEBUGGER;

SOFTDEBUGGER softdebugger; //The software debugger for the CPU!

//Command mode

//Next steps:

//First phase
void debugger_doError() //Give an error result!
{
	if (__HW_DISABLED) return; //Abort!
	softdebugger.command = 1; //Reset!
	softdebugger.readcommand = 1; //Give an error!
}

void debugger_doParameterPhase(word size) //Start a parameter phase!
{
	if (__HW_DISABLED) return; //Abort!
	softdebugger.command = 4; //Parameter phase when writing!
	softdebugger.readcommand = 4; //Abort on read!
	softdebugger.parameterpos = 0; //Reset parameter position!
	softdebugger.parametersize = size; //Set size of parameters!
}

//Execution phase
void debugger_ackParameters() //Acnowledge parameters!
{
	if (__HW_DISABLED) return; //Abort!
	softdebugger.parametersack = 1; //Acnowledge!
}

void debugger_doResultPhase(uint_32 size) //Start a result phase!
{
	if (__HW_DISABLED) return; //Abort!
	softdebugger.haveresult = 1; //We have a result!
	softdebugger.resultsize = size; //Set size of parameters!
}

//Functions that interpret given data:
void quitdebugger() //Quits the debugger!
{
	if (__HW_DISABLED) return; //Abort!
	softdebugger.command = 0; //Move back to unexisting mode!
	softdebugger.readcommand = 0; //We're reading the string again!
	//Newlines stay the same: we keep the current system!
}

void enterdebugger()
{
	if (__HW_DISABLED) return; //Abort!
	softdebugger.command  = 1; //Enter command mode!
	softdebugger.readcommand = 1; //Invalid read!
}

//Output filename support!
void outputfilename_specifylength()
{
	if (__HW_DISABLED) return; //Abort!
}

//The main handler function list!

typedef void (*DebuggerCommandHandler)();    /* A pointer to a command handler function */

DebuggerCommandHandler commandhandlers[1][1][3] = { //[group][command][0=basic,1=after parameters,2=Fill result]
	{ //Group 0
		{ //Function 0: Quit to debugger (always)
			quitdebugger, //Group 0, Command 0: Reset to debugger!
			NULL, //There are no parameters, so no after parameters!
			NULL //There is no result!
		},
		/*{ //Function 1: Change output filename: Specify length.
			outputfilename_specifylength,
			outputfilename_specifylength_processparameters
		}*/
	}
	};
	
//Basic command mode functionality!
void write_command(byte data) //Write functionality
{
	if (__HW_DISABLED) return; //Abort!
	switch (softdebugger.command) //What command?
	{
		case 1: //Group selection?
			if (data>NUMITEMS(commandhandlers)) //Too high?
			{
				softdebugger.readcommand = 1; //Invalid command/parameter!
			}
			else //Valid number?
			{
				softdebugger.readcommand = 2; //Valid command/parameter!
				softdebugger.command_group = data; //Set the command group!
				softdebugger.command = 2; //Goto high command!
			}
			break;
		case 2: //Command high?
			if (data>NUMITEMS(commandhandlers[0])) //Too high?
			{
				softdebugger.readcommand = 1; //Invalid command/parameter!
				softdebugger.command = 1; //Return to the standard: group selection!
			}
			else if (commandhandlers[softdebugger.command_group][data]==NULL) //Not used? Invalid command!
			{
				softdebugger.readcommand = 1; //Invalid command/parameter!
				softdebugger.command = 1; //Return to the standard: group selection!				
			}
			else //Valid command?
			{
				softdebugger.command_execution = data; //Set the command to be executed!
				softdebugger.readcommand = 2; //Valid command/parameter #2: after read, execute basic command!
				softdebugger.command = 3; //Execute basic after status read!
			}
			break;
		case 3: //Basic is executed on read, write does nothing!
			break;
		case 4: //Parameter(s)?
			softdebugger.parameterbuffer[softdebugger.parameterpos] = data; //Write data to the parameters!
			if (++softdebugger.parameterpos>=softdebugger.parametersize) //Size overflow?
			{
				softdebugger.readcommand = 2; //Valid command/parameter check?
				softdebugger.command = 5; //Parameter check execute!
			}
			break;
		case 5: //Too many parameters?
			//Ignore any input by the CPU!
			softdebugger.readcommand = 1; //Let the CPU know we have an invalid command/parameter/call specified!
			break;
		case 6: //Giving result mode? We cause the result mode to switch to validation mode to check if the read result is OK!
			softdebugger.readcommand = 4; //Result valid detection during reading!
			break;
	}
}

byte read_command() //Read functionality
{
	if (__HW_DISABLED) return 0; //Abort!
	byte result = ~0; //Result!
	switch (softdebugger.readcommand) //What read mode?
	{
		case 1: //Invalid command/parameter/action!
			softdebugger.command = 1; //Reset the command interpreter to find our next command!
			result = 0; //Invalid action!
			break;
		case 2: //Valid command/parameter!
			switch (softdebugger.command) //What command
			{
				case 1: //Plain OK message that's optional?
				case 2:
					result = 1; //OK!
					break;
				case 3: //Execute basic when Command given!
					result = 1; //We're an OK command!
					softdebugger.command = 1; //Default: reset to command mode!
					if (commandhandlers[softdebugger.command_group][softdebugger.command_execution][0]) //Valid?
					{
						commandhandlers[softdebugger.command_group][softdebugger.command_execution][0](); //Execute basic!
					}
					break;
				case 4: //Not enough parameters written?
					result = 1; //We're aborting!
					softdebugger.command = 1; //Reset to command mode!
					softdebugger.readcommand = 1; //Another read causes error (0)!
					break;
				case 5: //Parameters finished?
					softdebugger.command = 1; //Default: invalid parameter(s)!
					softdebugger.readcommand = 1; //Default: reset to invalid state!
					softdebugger.parametersack = 0; //Default: not acnowledged!
					if (commandhandlers[softdebugger.command_group][softdebugger.command_execution][1]) //Valid?
					{
						commandhandlers[softdebugger.command_group][softdebugger.command_execution][1](); //Execute function parameters!
					}
					if (softdebugger.parametersack) //Parameters acnowledged?
					{
						result = softdebugger.haveresult?3:2; //We have a result?
						if (softdebugger.haveresult) //Gotten a result? Move to the result phase!
						{
							softdebugger.command = 6; //End result phase on write!
							softdebugger.readcommand = 3; //Read gives results!
							softdebugger.resultpos = 0; //Reset parameter position!
						}
						else
						{
							softdebugger.command = 1; //Reset!
							softdebugger.readcommand = 1; //Read gives error!
						}
					}
					else
					{
						result = 0; //Error!
						softdebugger.command = 1; //Reset to command mode!
						softdebugger.readcommand = 1; //Another read causes error (0)!
					}
					break;
				default: //Unknown command mode?
					softdebugger.command = 1; //Reset the command interpreter to find our next command!
					softdebugger.readcommand = 1; //Reset to error!
					result = 0; //Invalid action!
					break;
			}
			break;
		case 3: //Result mode!
			if (!softdebugger.resultpos) //First result position?
			{
				softdebugger.resultoverflow = 1; //Underflow: not all is read!
				++softdebugger.resultpos; //Increase!
				return (softdebugger.resultsize&0xFF); //Lower size byte!
			}
			else if (softdebugger.resultpos==1) //Second result position?
			{
				softdebugger.resultoverflow = softdebugger.resultsize?1:0; //Give an underflow error when not all is read!
				++softdebugger.resultpos; //Increase!
				return ((softdebugger.resultsize&0xFF00)>>8); //High size byte!
			}
			uint_32 resultpos; //Result position?
			//Read result, if possible?
			resultpos = (softdebugger.resultpos-2); //Calculate result position!
			if (resultpos<softdebugger.resultsize) //Valid position?
			{
				result = softdebugger.resultbuffer[resultpos]; //Read the result!
				++softdebugger.resultpos; //Increase!
				softdebugger.resultoverflow = (resultpos!=softdebugger.resultsize); //Underflow when not fully read yet!
			}
			else
			{
				softdebugger.resultoverflow = 1; //Result overflow detected!
				//Position overflow leads to unknown data, but no action is taken against it for safety!
			}
			break;
		case 4: //Result OK/error mode! Also reset to command mode!
			result = softdebugger.resultoverflow?0:4; //We're either a clear (step 4 completed) or an error (0)!
			softdebugger.command = 1; //Reset to command mode!
			softdebugger.readcommand = 1; //Assert error mode on next read!
			break;
		default: //Unknown? Do nothing!
			break;
	}
	return result; //Give the result!
}











//Text (debugger) mode support!

void debugger_flush()
{
	if (__HW_DISABLED) return; //Abort!
	if (!strcmp(softdebugger.writtendata,debugger_identifier)) //Enter/reset debugger mode?
	{
		softdebugger.command = 1; //Enter command mode!
		softdebugger.readcommand = 1; //Read causes invalid data!
	}
	else if (!strcmp(softdebugger.writtendata,"")) //Plain output and not an empty line?
	{
		dolog(softdebugger.data.outputfilename,softdebugger.writtendata); //Add the written data to the debugger on a new line!
	}
	strcpy(softdebugger.writtendata,""); //Clear the data again!
}

void debugger_writecharacter(byte c) //Write a character to the debugger!
{
	if (__HW_DISABLED) return; //Abort!
	if ((c=='\n') || (c=='\r')) //Newline character?
	{
		//we count \n, \r, \n\r and \r\n as the same: newline!
		if (!softdebugger.newline) //First newline character?
		{
			debugger_flush(); //Flush!
			softdebugger.newline = c; //Detect for further newlines!
		}
		else //Second newline+?
		{
			if (softdebugger.newline==c) //Same newline as before?
			{
				debugger_flush(); //Flush!
				//Continue counting newlines!
			}
			else //No newline, clear the newline flag!
			{
				softdebugger.newline = 0; //Not a newline anymore!
			}
		}
	}
	else //Normal character?
	{
		sprintf(softdebugger.writtendata,"%s%c",softdebugger.writtendata,c); //Add to the debugged data!
	}
}

//Write and read functionality!
byte PORT_writeDebugger(word port, byte data)
{
	if (__HW_DISABLED) return 0; //Abort!
	if (port != 0xE9) return 0; //Not our port!
	debugger_writecharacter(data); //Write the character to the debugger!
	return 1; //OK!
}

byte PORT_readDebugger(word port, byte *result)
{
	if (__HW_DISABLED) return 0; //Undefined port?
	if (port != 0xE9) return 0; //Not our port!
	*result = 0xE9; //Identifier for identifying our debugger!
	return 1; //Give the result!
}

byte PORT_writeCommand(word port, byte data)
{
	if (__HW_DISABLED) return 0; //Abort!
	if (port != 0xEA) return 0; //Not our port!
	if (softdebugger.command) //Identifier read or in command mode?
	{
		write_command(data); //Process a command write!
		return 1; //OK!
	}
	return 0; //Not in command mode!
}

byte PORT_readCommand(word port, byte *result) //Read from the debugger port! Undefined on real systems!
{
	if (__HW_DISABLED) return 0; //Abort!
	if (port != 0xEA) return 0; //Not our port!
	if (!softdebugger.readcommand) //Undefined? Give our identifier followed by 0xFF!
	{
		if (softdebugger.identifier_pos<strlen(debugger_identifier)) //Not end-of-string?
		{
			*result = debugger_identifier[softdebugger.identifier_pos++]; //Read a character from the identifier!
		}
		else //Final character?
		{
			*result = 0xFF; //End of string identifier!
			softdebugger.identifier_pos = 0; //Reset position!
		}
		return 1; //Give the result!
	}
	*result = read_command(); //We're in command mode, so read from the command interpreter!
	return 1; //Give the result!
}

//Initialisation of the debugger!
void BIOS_initDebugger() //Init software debugger!
{
	if (__HW_DISABLED) return; //Abort!
	//First: initialise all hardware ports for emulating!
	register_PORTOUT(&PORT_writeDebugger); //Basic: debugger registers!
	register_PORTIN(&PORT_readDebugger); //Basic: debugger identification!
	//Command registers!
	register_PORTIN(&PORT_readCommand); //Read a command byte!
	register_PORTOUT(&PORT_writeCommand); //Write a command byte!
	bzero(softdebugger.data.outputfilename,sizeof(softdebugger.data.outputfilename)); //Init output filename!
	strcpy(softdebugger.data.outputfilename,"debugger"); //We're logging to debugger by default!
	quitdebugger(); //First controller reset!
}

void BIOS_doneDebugger() //Finish debugger!
{
	if (__HW_DISABLED) return; //Abort!
	if (!strcmp(softdebugger.writtendata,"")) //Still data buffered?
	{
		debugger_flush(); //Write the rest of the characters written to the output!
	}
}