#ifndef DSKIMAGE_H
#define DSKIMAGE_H

#include "headers/types.h" //Basic types!

//One disk info block per file!
#include "headers/packed.h" //Start packed structure!
typedef struct
{
	byte ID[34];
	byte NameOfCreator[14];
	byte NumberOfTracks;
	byte NumberOfSides;
	word TrackSize;
	byte unused[204];
} DISKINFORMATIONBLOCK;
#include "headers/endpacked.h" //End packed structure!

//One track information block per track
#include "headers/packed.h" //Start packed structure!
typedef struct
{
	byte ID[12];
	uint_32 unused1[4];
	byte tracknumber;
	byte sidenumber;
	word unused2;
	byte sectorsize;
	byte numberofsectors;
	byte GAP3Length;
} TRACKINFORMATIONBLOCK;
#include "headers/endpacked.h" //End packed structure!

//One sector information block per sector.
#include "headers/packed.h" //Start packed structure!
typedef struct
{
	byte track;
	byte side;
	byte SectorID;
	byte SectorSize; //2^SectorSize=Size. For SectorSize=6, only 0x1800 bytes are stored.
	byte ST1;
	byte ST2;
	word notused;
} SECTORINFORMATIONBLOCK;
#include "headers/endpacked.h" //End packed structure!

byte is_DSKimage(char *filename); //Are we a DSK image?
byte readDSKInfo(char *filename, DISKINFORMATIONBLOCK *result); //Read global DSK information!
byte readDSKTrackInfo(char *filename, byte side, byte track, TRACKINFORMATIONBLOCK *result);
byte readDSKSectorInfo(char *filename, byte side, byte track, byte sector, SECTORINFORMATIONBLOCK *result); //Read DSK sector information!
byte readDSKSectorData(char *filename, byte side, byte track, byte sector, byte sectorsize, void *result); //Read a sector from the DSK file!
byte writeDSKSectorData(char *filename, byte side, byte track, byte sector, byte sectorsize, void *sectordata); //Write a sector to the DSK file!

#endif