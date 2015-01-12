#ifndef THREADS_H
#define THREADS_H

#include "headers/types.h" //Basic type support!
#include <SDL/SDL_thread.h> //Multithreading support!

#define DEFAULT_PRIORITY 0x18
//Default priority for threads!

typedef struct
{
int used; //Used thread?
Handler callback; //The callback to use!
byte status; //Used thread entries status: 0=Allocated, 1=Created, 2=Running! All else is invalid: regard as NULL record, only allocated!
char name[256]; //Names of the threads (just for debugging)
SDL_Thread *thread; //The specified thread in SDL!
uint_32 threadID; //The specified thread ID!
} ThreadParams, *ThreadParams_p; //The thread's params!

void initThreads(); //Initialise&reset thread subsystem!
ThreadParams_p startThread(Handler thefunc, char *name, int priority); //Start a thread, gives the thread info if successfull!
byte threadRunning(ThreadParams_p thread, char *name); //Is this thread running?
void waitThreadEnd(ThreadParams_p thread); //Wait for this thread to end!
void quitThread(); //Quit the current thread!
void termThread(); //Alias of quitThread!
void termThreads(); //Terminate all threads but our own (active thread)!
int ThreadsRunning(); //Are there any threads running or ready to run?
int minthreadsrunning(); //Minimum ammount of threads running when nothing's there!
#endif