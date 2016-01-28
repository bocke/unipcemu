#ifndef __EMU_WIN_H
#define __EMU_WIN_H

#include "headers/types_base.h" //Base types!

//Normal SDL libraries
#include "SDL.h" //SDL library for windows!
#include "SDL_events.h" //SDL events!

//Convert the current info to support Visual C++ vs MinGW/GNU detection!
#ifdef _WIN32
#ifndef __GNUC__
#ifndef __MINGW32__
#pragma comment(lib, "User32.lib")
#ifndef VISUALC
#define VISUALC
#endif
#endif
#endif
#endif


//Windows specific structures!
#ifdef VISUALC
#include <direct.h> //For mkdir and directory support! Visual C++ only!
#endif

#include <windows.h> //Both for Visual c++ and MinGW/GNU, this is used!

#define realdelay(x) (x)

#define delay(us) SDL_Delay(realdelay((uint_32)((us)/1000)))
#define sleep() for (;;) delay(1000000)

#ifdef VISUALC
//Visual C++ needs the result!
#define domkdir(dir) int ok = _mkdir(dir)
#else
//Don't use the result with MinGW!
#define domkdir(dir) _mkdir(dir)
#endif

//INLINE options!
#ifdef OPTINLINE
#undef OPTINLINE
#endif

#ifdef __ENABLE_INLINE
//For some reason inline functions don't work on windows?
#define OPTINLINE __inline
#else
#define OPTINLINE
#endif

//Enum safety
#define ENUM8 :byte
#define ENUMS8 :sbyte
#define ENUM16 :word
#define ENUMS16 :sword
#define ENUM32 :uint_32
#define ENUMS32 :int_32

#ifdef _WIN64
typedef uint_64 ptrnum;
#else
typedef uint_32 ptrnum;
#endif

#endif
