#include "headers/types.h" //Basic type support etc.
#include "headers/cpu/cpu.h" //CPU support!
#include "headers/emu/gpu/gpu.h" //Need GPU comp!
#include "headers/cpu/cpu_OP8086.h" //8086 interrupt instruction support!
#include "headers/bios/bios.h" //BIOS Support!
#include "headers/emu/debugger/debugger.h" //Debugger support!
#include "headers/cpu/easyregs.h" //Easy register addressing!

#include "headers/emu/gpu/gpu_emu.h" //GPU EMU support!
#include "headers/interrupts/interrupt10.h" //Interrupt 10h support!
#include "headers/emu/timers.h" //Timer support!
#include "headers/support/log.h" //Logging support!

//Shutdown the application when an unknown instruction is executed?
//#define UNKOP_SHUTDOWN

void halt_modrm(char *message, ...) //Unknown modr/m?
{
	stopVideo(); //Need no video!
	stopTimers(0); //Stop all normal timers!
	char buffer[256]; //Going to contain our output data!
	va_list args; //Going to contain the list!
	va_start (args, message); //Start list!
	vsprintf (buffer, message, args); //Compile list!
	va_end (args); //Destroy list!
	raiseError("modrm","Modr/m error: %s",buffer); //Shut the adress and opcode!
	debugger_screen(); //Show debugger info!
//EMU_Shutdown(1); //Shut down the emulator!
	sleep(); //Wait forever!
}

extern word CPU_exec_CS;
extern uint_32 CPU_exec_EIP;

extern word CPU_exec_lastCS; //OPCode CS
extern uint_32 CPU_exec_lastEIP; //OPCode EIP

//Normal instruction #UD handlers for 80(1)8X+!
void unkOP_8086() //Unknown opcode on 8086?
{
	//dolog("8086","Unknown opcode on 8086: %02X",CPU[activeCPU].lastopcode); //Last read opcode!
	CPU_unkOP(); //Execute the unknown opcode exception handler, if any!
	#ifdef UNKOP_SHUTDOWN
	dolog("unkOP","Unknown 8086 opcode detected: %02X@%04X:%04X, Previous opcode: %02X@%04X(Physical %08X):%04X",CPU[activeCPU].lastopcode,CPU_exec_CS,CPU_exec_EIP,CPU[activeCPU].previousopcode,CPU_exec_lastCS,CPU[activeCPU].previousCSstart,CPU_exec_lastEIP); //Log our info!
	EMU_Shutdown(1); //Request to shut down!
	#endif
}

void unkOP_186() //Unknown opcode on 186+?
{
	debugger_setcommand("<NECV20/V30+ #UD>"); //Command is unknown opcode!
	//dolog("unkop","Unknown opcode on NECV30+: %02X",CPU[activeCPU].lastopcode); //Last read opcode!
	CPU_resetOP(); //Go back to the opcode itself!
	CPU086_int(EXCEPTION_INVALIDOPCODE); //Call interrupt with return addres of the OPcode!
	CPU[activeCPU].faultraised = 1; //We've raised a fault!
	#ifdef UNKOP_SHUTDOWN
	dolog("unkOP","Unknown opcode detected: %02X@%04X:%08X, Previous opcode: %02X@%04X(Physical %08X):%08X",CPU[activeCPU].lastopcode,CPU_exec_CS,CPU_exec_EIP,CPU[activeCPU].previousopcode,CPU_exec_lastCS,CPU[activeCPU].previousCSstart,CPU_exec_lastEIP); //Log our info!
	EMU_Shutdown(1); //Request to shut down!
	#endif
}

//0F opcode extensions #UD handler
void unkOP0F_286() //0F unknown opcode handler on 286+?
{
	debugger_setcommand("<80286+ 0F #UD>"); //Command is unknown opcode!
	//dolog("unkop","Unknown 0F opcode on 80286+: %02X",CPU[activeCPU].lastopcode); //Last read opcode!
	CPU_resetOP(); //Go back to the opcode itself!
	CPU086_int(EXCEPTION_INVALIDOPCODE); //Call interrupt!
	CPU[activeCPU].faultraised = 1; //We've raised a fault!
	#ifdef UNKOP_SHUTDOWN
	dolog("unkOP","Unknown 0F opcode detected: %02X@%04X:%08X, Previous opcode: %02X@%04X(Physical %08X):%08X",CPU[activeCPU].lastopcode,CPU_exec_CS,CPU_exec_EIP,CPU[activeCPU].previousopcode,CPU_exec_lastCS,CPU[activeCPU].previousCSstart,CPU_exec_lastEIP); //Log our info!
	EMU_Shutdown(1); //Request to shut down!
	#endif
}

//0F opcode extensions #UD handler
void unkOP0F_386() //0F unknown opcode handler on 286+?
{
	debugger_setcommand("<80386+ 0F #UD>"); //Command is unknown opcode!
	//dolog("unkop","Unknown 0F opcode on 80286+: %02X",CPU[activeCPU].lastopcode); //Last read opcode!
	CPU_resetOP(); //Go back to the opcode itself!
	CPU086_int(EXCEPTION_INVALIDOPCODE); //Call interrupt!
	CPU[activeCPU].faultraised = 1; //We've raised a fault!
	#ifdef UNKOP_SHUTDOWN
	dolog("unkOP","Unknown 386+ 0F opcode detected: %02X@%04X:%08X, Previous opcode: %02X@%04X(Physical %08X):%08X",CPU[activeCPU].lastopcode,CPU_exec_CS,CPU_exec_EIP,CPU[activeCPU].previousopcode,CPU_exec_lastCS,CPU[activeCPU].previousCSstart,CPU_exec_lastEIP); //Log our info!
	EMU_Shutdown(1); //Request to shut down!
	#endif
}