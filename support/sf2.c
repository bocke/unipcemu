#include "headers/types.h" //Basic types!
#include "headers/support/sf2.h" //Our typedefs!
#include "headers/support/zalloc.h" //ZAlloc support!
#include "headers/support/log.h" //Logging support!
#include "headers/support/signedness.h" //Signedness support!

/*

First, all RIFF support!

*/

/*

getRIFFChunkSize: Retrieves the chunk size from an entry!

*/

uint_32 RIFF_entryheadersize(RIFF_ENTRY container) //Checked & correct!
{
	uint_32 result = 0; //Default: not found!
	RIFF_DATAENTRY temp;
	if (memprotect(container.voidentry,sizeof(temp),NULL)) //Valid entry?
	{
		memcpy(&temp,container.voidentry,sizeof(temp));
		if ((temp.ckID==CKID_LIST) || (temp.ckID==CKID_RIFF)) //Valid RIFF/LIST type?
	    {
	    	if (memprotect(container.voidentry,sizeof(*container.listentry),NULL))
	    	{
	    		result = sizeof(*container.listentry); //Take as list entry!
	    	}
	    }
	    else if (memprotect(container.voidentry,sizeof(*container.dataentry),NULL)) //Valid data entry?
	    {
	    	result = sizeof(*container.dataentry); //Take as data entry!
		}
	}
	return result; //Invalid entry!
}

uint_32 getRIFFChunkSize(RIFF_ENTRY entry) //Checked & correct!
{
	uint_32 chunksize;
	RIFF_DATAENTRY data;
	if (!memprotect(entry.voidentry,sizeof(data),NULL)) //Invalid entry?
	{
		return 0; //Default: Invalid entry protection!
	}
	memcpy(&data,entry.voidentry,sizeof(data)); //Copy for usage! 
	chunksize = data.ckSize; //The chunk size!
	if ((data.ckID==CKID_RIFF) || (data.ckID==CKID_LIST)) //We're a RIFF/LIST list?
	{
		chunksize += sizeof(*entry.dataentry); //The index is too long: it counts from the end of an data entry, including the extra ID data.
		chunksize -= sizeof(*entry.listentry); //Take off the size too large for the final result!
	}
	return chunksize; //Give the size!
}

void *RIFF_start_data(RIFF_ENTRY container, uint_32 headersize)
{
	byte *result;
	uint_32 size;
	if (!headersize) return NULL; //Invalid data!
	result = container.byteentry;
	result += headersize; //Take as data entry!
	size = getRIFFChunkSize(container); //Get the chunk size!
	if (size)
	{
		if (size&1) ++size; //Word align!
		if (memprotect(result,size,NULL)) //Valid?
		{
			return result; //Give the result!
		}
	}
	return NULL; //Invalid data!
}

OPTINLINE RIFF_ENTRY NULLRIFFENTRY()
{
	RIFF_ENTRY result;
	result.voidentry = NULL;
	return result; //Give the result!
}

/*

checkRIFFChunkLimits: Verify if a chunk within another chunk is valid to read (within range of the parent chunk)!

*/

byte checkRIFFChunkLimits(RIFF_ENTRY container, void *entry, uint_32 entrysize) //Check an entry against it's limits!
{
	uint_32 containersize;
	uint_32 containerstart, containerend, entrystart, entryend;
	void *startData; //Start of the data!
	if (!memprotect(container.voidentry,sizeof(RIFF_DATAENTRY),NULL)) //Error?
	{
		return 0; //Invalid address!
	}

	containersize = RIFF_entryheadersize(container); //What header size?
	if (!containersize) return 0; //Invalid container!

	if (!memprotect(container.voidentry,containersize,NULL)) //Error?
	{
		return 0; //Invalid address!
	}

	startData = RIFF_start_data(container,containersize); //Get the start of the container data!
	containersize = getRIFFChunkSize(container); //Get the size of the content of the container!

	if (!memprotect(startData,containersize,NULL)) //Invalid data?
	{
		return 0; //Invalid container data!
	}


	containerend = containerstart = (uint_32)startData;
	containerend += containersize; //What size!

	entryend = entrystart = (uint_32)entry; //Start of the data!
	entryend += entrysize;

	if (entrystart<containerstart) //Out of container bounds (low)?
	{
		return 0; //Out of bounds (low)!
	}
	if (entryend>containerend) //Out of container bounds (high)?
	{
		return 0; //Out of bounds (high)!
	}
	return 1; //OK!
}

/*

getRIFFEntry: Retrieves an RIFF Entry from a RIFF Chunk!

*/

RIFF_ENTRY getRIFFEntry(RIFF_ENTRY RIFFHeader, FOURCC RIFFID) //Read a RIFF Subchunk from a RIFF chunk.
{
	RIFF_LISTENTRY listentry;
	RIFF_DATAENTRY dataentry;
	
	RIFF_ENTRY EntriesStart;
	RIFF_ENTRY CurrentEntry;
	uint_32 foundid;
	RIFF_ENTRY temp_entry;
	uint_32 headersize; //Header size, precalculated!
	if (!RIFFHeader.dataentry) return NULLRIFFENTRY(); //Invalid RIFF Entry specified!
	if (!memprotect(RIFFHeader.dataentry,sizeof(*RIFFHeader.dataentry),NULL)) //Error?
	{
		return NULLRIFFENTRY(); //Invalid RIFF Header!
	}
	
	//Our entries for our usage!
	EntriesStart = RIFFHeader;
	CurrentEntry.voidentry = RIFF_start_data(RIFFHeader,RIFF_entryheadersize(RIFFHeader)); //Start of the data!

	if (!CurrentEntry.voidentry) return NULLRIFFENTRY(); //Invalid RIFF Header data!

	memcpy((void *)&dataentry,RIFFHeader.voidentry,sizeof(dataentry));
	
	foundid = dataentry.ckID; //Default: the standard ID specified!
	if ((foundid==CKID_LIST) || (foundid==CKID_RIFF)) //List type?
	{
		memcpy((void *)&listentry,RIFFHeader.voidentry,sizeof(listentry));
		foundid = listentry.fccType; //Take what the list type is!
	}
	
	for (;;) //Start on contents!
	{
		headersize = RIFF_entryheadersize(CurrentEntry); //The size of the current header!
		if (!checkRIFFChunkLimits(RIFFHeader,CurrentEntry.voidentry,headersize)) //Entry of bounds?
		{
			return NULLRIFFENTRY(); //Not found!
		}
		if (!checkRIFFChunkLimits(RIFFHeader,RIFF_start_data(CurrentEntry,headersize),getRIFFChunkSize(CurrentEntry))) //Data out of bounds?
		{
			return NULLRIFFENTRY(); //Not found!
		}
		memcpy(&dataentry,CurrentEntry.voidentry,sizeof(dataentry)); //Copy a data entry!
		foundid = dataentry.ckID; //Default: the standard ID specified!
		if ((foundid==CKID_LIST) || (foundid==CKID_RIFF)) //List type?
		{
			memcpy(&listentry,CurrentEntry.voidentry,sizeof(listentry)); //Copy a list entry!
			foundid = listentry.fccType; //Take what the list type is!
		}
		if (foundid==RIFFID) //Found the entry?
		{
			return CurrentEntry; //Give the entry!
		}
		//Entry not found?
		temp_entry.voidentry = RIFF_start_data(CurrentEntry,headersize); //Goto our start!
		temp_entry.byteentry += getRIFFChunkSize(CurrentEntry); //Add to the position of the start of the data!
		CurrentEntry.voidentry = temp_entry.voidentry; //Get the next entry!
	}
}

/*

getRIFFData: Gives data from a RIFF Chunk.
parameters:
	RIFFHeader: The Chunk to retrieve from.
	index: The entry number within the chunk.
	size: The size of a data entry.
result:
	NULL: Invalid entry, else the entry.

*/

byte getRIFFData(RIFF_ENTRY RIFFHeader, uint_32 index, uint_32 size, void *result)
{
	RIFF_DATAENTRY temp;
	byte *entrystart;
	if (!memprotect(RIFFHeader.voidentry,sizeof(*RIFFHeader.dataentry),NULL)) //Error?
	{
		return 0; //Invalid RIFF entry!
	}
	memcpy(&temp,RIFFHeader.voidentry,sizeof(temp)); //Get an entry!
	if ((temp.ckID==CKID_LIST) || (temp.ckID==CKID_RIFF)) //Has subchunks, no data?
	{
		return 0; //Invalid entry: we're a list, not data!
	}
	entrystart = (byte *)RIFF_start_data(RIFFHeader,RIFF_entryheadersize(RIFFHeader)); //Start of the data!
	if (!entrystart) //Error?
	{
		return 0; //Invalid entry: couldn't get the start of the data!
	}
	entrystart += (index*size); //Get the start index in memory!
	if (!checkRIFFChunkLimits(RIFFHeader,entrystart,size)) //Invalid data?
	{
		return 0; //Invalid entry!
	}
	memcpy(result,entrystart,size); //Copy the data to the result, aligned if needed!
	return 1; //Give the entry that's valid!
}

/*

Next, Basic FLAG_SF open/close support!

*/

byte validateSF(RIFFHEADER *RIFF) //Validate a soundfont file!
{
	uint_32 filesize;
	uint_32 finalentry; //For determining the final entry number!
	uint_64 detectedsize;
	RIFF_ENTRY sfbkentry, infoentry, version, soundentries, hydra, phdr, pbag, pmod, pgen, inst, ibag, imod, igen, shdr;
	sfVersionTag versiontag;
	sfPresetHeader finalpreset;
	sfPresetBag finalpbag;
	sfInst finalInst;
	sfInstBag finalibag;
	if (memprotect(RIFF,sizeof(RIFFHEADER),NULL)!=RIFF) //Error?
	{
		dolog("SF2","validateSF: Archive pointer is invalid!");
		return 0; //Not validated: invalid structure!
	}
	//First, validate the RIFF file structure!
	filesize = RIFF->filesize; //Get the file size from memory!
	if (memprotect(RIFF->rootentry.dataentry,filesize,NULL)!=RIFF->rootentry.dataentry) //Out of bounds in the memory module?
	{
		dolog("SF2","validateSF: Root entry pointer is invalid:!");
		return 0; //Not validated: invalid memory!
	}
	if (RIFF->rootentry.listentry->ckID!=CKID_RIFF) //Not a soundfont block?
	{
		dolog("SF2","validateSF: RIFF Header is invalid!");
		return 0; //Not validated: not a RIFF file!
	}
	detectedsize = (getRIFFChunkSize(RIFF->rootentry)+RIFF_entryheadersize(RIFF->rootentry));
	if (detectedsize!=filesize) //Not the entire file? (we have multiple entries?)
	{
		dolog("SF2","validateSF: File has multiple entries: size detected: %i bytes, total: %i bytes; header: %i bytes!",detectedsize,filesize,RIFF_entryheadersize(RIFF->rootentry));
		return 0; //Not validated: invalid soundfont header (multiple headers not allowed)!
	}
	//Global OK!

	//Now check for precision content!
	if (RIFF->rootentry.listentry->fccType!=CKID_SFBK) //Not a soundfont?
	{
		return 0; //Not validated: invalid soundfont header!
	}

	sfbkentry = RIFF->rootentry; //SFBK!
	if (!sfbkentry.listentry)
	{
		dolog("SF2","validateSF: SFBK Entry not found!");
		return 0; //Invalid SFBK!
	}
	
	//The root of our structure is intact, look further!
	
	infoentry = getRIFFEntry(RIFF->rootentry,CKID_INFO); //Get the info block!
	version = getRIFFEntry(infoentry,CKID_IFIL); //Get the version!
	if (!version.dataentry) //Not found?
	{
		dolog("SF2","validateSF: Version Entry not found!");
		return 0; //Not found!
	}
	if (getRIFFChunkSize(version)!=4) //Invalid size?
	{
		dolog("SF2","validateSF: Version has invalid size!");
		return 0; //Invalid size!
	}
	
	if (!getRIFFData(version,0,sizeof(sfVersionTag),&versiontag)) //Not gotten the data?
	{
		dolog("SF2","validateSF: Version Entry not retrieved!");
		return 0; //Couldn't get RIFF data!
	}
	if (versiontag.wMajor>2) //Too high major version?
	{
		dolog("SF2","validateSF: Invalid major version: %i!",versiontag.wMajor);
		return 0; //Invalid version!
	}
	if (versiontag.wMajor==2 && versiontag.wMinor>4) //Too high?
	{
		dolog("SF2","validateSF: Invalid minor version: %i!",versiontag.wMinor);
		return 0; //Invalid version!
	}
	//We're build arround the 2.04 specification!
	
	soundentries = getRIFFEntry(RIFF->rootentry,CKID_SDTA); //Check for the sound entries!
	RIFF->pcmdata = getRIFFEntry(soundentries,CKID_SMPL); //Found samples?
	if (!RIFF->pcmdata.dataentry) //Sample data not found?
	{
		dolog("SF2","validateSF: PCM samples not found!");
		return 0; //No sample data found!
	}
	
	RIFF->pcm24data = getRIFFEntry(soundentries,CKID_SM24); //Found 24-bit samples? If acquired, use it!

	//Check PHDR structure!
	RIFF->hydra = hydra = getRIFFEntry(RIFF->rootentry,CKID_PDTA); //Get the HYDRA structure!
	if (!hydra.dataentry)
	{
		dolog("SF2","validateSF: HYDRA block not found!");
		return 0; //No PDTA found!
	}
	
	//First, check the presets!
	RIFF->phdr = phdr = getRIFFEntry(hydra,CKID_PHDR); //Get the PHDR data!
	if (SAFEMOD(getRIFFChunkSize(phdr),38)) //Not an exact multiple of 38 bytes?
	{
		dolog("SF2","validateSF: PHDR block not found!");
		return 0; //Corrupt file!
	}
	
	finalentry = SAFEDIV(getRIFFChunkSize(phdr),sizeof(sfPresetHeader));
	--finalentry; //One less than the size in entries is our entry!

	if (!getRIFFData(phdr,finalentry,sizeof(sfPresetHeader),&finalpreset)) //Failed to get the PHDR data?
	{
		dolog("SF2","validateSF: Invalid final preset entry!");
		return 0; //Corrupt file!
	}

	if (!finalentry) //Nothing there?
	{
		dolog("SF2","validateSF: Missing final preset entry!");
		return 0; //No instruments found!
	}
	
	//Check PBAG size!
	RIFF->pbag = pbag = getRIFFEntry(hydra,CKID_PBAG); //Get the PBAG structure!
	if (SAFEMOD(getRIFFChunkSize(pbag),4)) //Not a multiple of 4?
	{
		dolog("SF2","validateSF: PBAG chunk size isn't a multiple of 4 bytes!");
		return 0; //Corrupt file!
	}
	if (!getRIFFData(pbag,finalpreset.wPresetBagNdx,sizeof(sfPresetBag),&finalpbag)) //Final not found?
	{
		dolog("SF2","validateSF: Final PBAG couldn't be retrieved!");
		return 0; //Corrupt file!
	}
	
	RIFF->pmod = pmod = getRIFFEntry(hydra,CKID_PMOD);
	if (!pmod.dataentry)
	{
		dolog("SF2","validateSF: PMOD chunk is missing!");
		return 0; //Corrupt file!
	}
	if (getRIFFChunkSize(pmod)!=((10*finalpbag.wModNdx)+10)) //Invalid PMOD size?
	{
		dolog("SF2","validateSF: Invalid PMOD chunk size!");
		return 0;
	}

	RIFF->pgen = pgen = getRIFFEntry(hydra,CKID_PGEN);
	if (!pgen.dataentry)
	{
		dolog("SF2","validateSF: PGEN chunk is missing!");
		return 0; //Corrupt file!
	}
	if (getRIFFChunkSize(pgen)!=((finalpbag.wGenNdx<<2)+4)) //Invalid PGEN size?
	{
		dolog("SF2","validateSF: Invalid PGEN chunk size: %i; Expected %i!",getRIFFChunkSize(pgen),((finalpbag.wGenNdx<<2)+4));
		return 0;
	}
	if (SAFEMOD(getRIFFChunkSize(pgen),4)) //Not a multiple of 4?
	{
		dolog("SF2","validateSF: PGEN chunk size isn't a multiple of 4 bytes!");
		return 0; //Corrupt file!
	}
	
	RIFF->inst = inst = getRIFFEntry(hydra,CKID_INST);
	if (!inst.dataentry)
	{
		dolog("SF2","validateSF: INST chunk is missing!");
		return 0; //Corrupt file!
	}
	if (SAFEMOD(getRIFFChunkSize(inst),22)) //Not a multiple of 22?
	{
		dolog("SF2","validateSF: INST chunk size isn't a multiple of 22 bytes!");
		return 0; //Corrupt file!
	}
	if (getRIFFChunkSize(inst)<(sizeof(sfInst)<<1)) //Too few records?
	{
		dolog("SF2","validateSF: The INST chunk has too few records!");
		return 0; //Corrupt file!
	}
	finalentry = SAFEDIV(getRIFFChunkSize(inst),sizeof(sfInst));
	--finalentry; //One less!

	if (!getRIFFData(inst,finalentry,sizeof(sfInst),&finalInst)) //Failed to get the record?
	{
		dolog("SF2","validateSF: INST chunk final entry couldn't be retrieved!");
		return 0; //Corrupt file!
	}

	RIFF->ibag = ibag = getRIFFEntry(hydra,CKID_IBAG);
	if (!ibag.dataentry)
	{
		dolog("SF2","validateSF: IBAG chunk is missing!");
		return 0; //Corrupt file!
	}
	if (getRIFFChunkSize(ibag)!=((4*finalInst.wInstBagNdx)+4))
	{
		dolog("SF2","validateSF: Invalid IBAG chunk size!");
		return 0; //Corrupt file!
	}
	if (SAFEMOD(getRIFFChunkSize(ibag),4)) //Not a multiple of 4?
	{
		dolog("SF2","validateSF: IBAG chunk size isn't a multiple of 4 bytes!");
		return 0; //Corrupt file!
	}
	if (getRIFFChunkSize(ibag)<(sizeof(sfInstBag)<<1)) //Too few records?
	{
		dolog("SF2","validateSF: IBAG chunk has too few records!");
		return 0; //Corrupt file!
	}
	if (!getRIFFData(ibag,finalInst.wInstBagNdx,sizeof(sfInstBag),&finalibag)) //Failed to get the records?
	{
		dolog("SF2","validateSF: IBAG chunk final entry couldn't be retrieved!");
		return 0; //Corrupt file!
	}

	//imod size=10xfinal instrument.wModNdx+10
	
	RIFF->imod = imod = getRIFFEntry(hydra,CKID_IMOD);
	if (!imod.dataentry)
	{
		dolog("SF2","validateSF: IMOD chunk is missing!");
		return 0; //Corrupt file!
	}
	if (getRIFFChunkSize(imod)!=((10*finalibag.wInstModNdx)+10))
	{
		dolog("SF2","validateSF: Invalid INST chunk size!");
		return 0; //Corrupt file!
	}
	if (SAFEMOD(getRIFFChunkSize(imod),10)) //Not a multiple of 10?
	{
		dolog("SF2","validateSF: INST chunk isn't a multiple of 10 bytes!");
		return 0; //Corrupt file?
	}
	
	//igen size=4xterminal instrument.wGenNdx+4
	RIFF->igen = igen = getRIFFEntry(hydra,CKID_IGEN);
	if (!igen.dataentry)
	{
		dolog("SF2","validateSF: IGEN chunk is missing!");
		return 0; //Corrupt file!
	}
	if (getRIFFChunkSize(igen)!=((4*finalibag.wInstGenNdx)+4))
	{
		dolog("SF2","validateSF: Invalid IGEN chunk size!");
		return 0; //Corrupt file!
	}
	if (SAFEMOD(getRIFFChunkSize(igen),4)) //Not a multiple of 4?
	{
		dolog("SF2","validateSF: IGEN chunk size isn't a multiple of 4 bytes!");
		return 0; //Corrupt file?
	}
	
	RIFF->shdr = shdr = getRIFFEntry(hydra,CKID_SHDR);
	if (!shdr.dataentry)
	{
		dolog("SF2","validateSF: SHDR chunk is missing!");
		return 0; //Corrupt file!
	}
	if (SAFEMOD(getRIFFChunkSize(shdr),46))
	{
		dolog("SF2","validateSF: SHDR chunk isn't a multiple of 46 bytes!");
		return 0; //Corrupt file!
	}
	
	//The RIFF file has been validated!
	return 1; //Validated!
}

RIFFHEADER *readSF(char *filename)
{
	
	FILE *f;
	uint_32 filesize;
	byte *buffer;
	RIFFHEADER *riffheader;
	f = fopen(filename,"rb"); //Read the file!
	if (!f)
	{
		return NULL; //Error!
	}
	fseek(f,0,SEEK_END); //Goto EOF!
	filesize = ftell(f); //Look for the size!
	fseek(f,0,SEEK_SET); //Goto BOF!
	if (!filesize) //No size?
	{
		dolog("SF2","Error: Soundfont %s is empty!",filename);
		fclose(f); //Close!
		return NULL; //File has no size!
	}
	buffer = (byte *)zalloc(filesize+sizeof(RIFFHEADER),"RIFF_FILE",NULL); //A RIFF file entry in memory!
	if (!buffer) //Not enough memory?
	{
		dolog("SF2","Error: Ran out of memory to allocate the soundfont!");
		fclose(f); //Close the file!
		return NULL; //Error allocating the file!
	}
	riffheader = (RIFFHEADER *)buffer; //Convert to integer!
	riffheader->filesize = filesize; //Save the file size for checking!
	riffheader->rootentry.byteentry = (byte *)buffer+sizeof(RIFFHEADER); //Start of the data!
	if (fread(riffheader->rootentry.voidentry,1,filesize,f)!=filesize) //Error reading to memory?
	{
		dolog("SF2","Error: %s could not be read!",filename);
		fclose(f); //Close the file!
		freez((void **)&buffer,filesize,"RIFF_FILE"); //Free the file!
		return NULL; //Error!
	}
	fclose(f); //Close the file!
	if (validateSF(riffheader)) //Give the allocated buffer with the file!
	{
		return riffheader; //Give the result!
	}
	dolog("SF2","Error: The soundfont %s is corrupt!",filename);
	freez((void **)buffer,filesize+sizeof(RIFFHEADER),"RIFF_FILE"); //Release the buffer!
	return NULL; //Invalid soundfont!
}

void closeSF(RIFFHEADER **sf)
{
	RIFFHEADER *thesoundfont = *sf;
	uint_32 filesize;
	if (!memprotect(thesoundfont,sizeof(RIFFHEADER),"RIFF_FILE")) //Invalid header?
	{
		*sf = NULL; //Invalidate!
		return; //Abort!
	}
	filesize = thesoundfont->filesize;
	if (!filesize) //Invalid size?
	{
		*sf = NULL; //Invalidate!
		return; //Abort!
	}
	freez((void **)sf,filesize+sizeof(RIFFHEADER),"RIFF_FILE"); //Free the data!
}

/*

Basic reading functions for presets, instruments and samples.

*/

OPTINLINE RIFF_ENTRY getHydra(RIFFHEADER *sf) //Retrieves the HYDRA structure from the soundfont!
{
	return sf->hydra; //Give the hydra block!
}

//Preset!
byte getSFPreset(RIFFHEADER *sf, uint_32 preset, sfPresetHeader *result)
{
	return getRIFFData(sf->phdr,preset,sizeof(sfPresetHeader),result); //Give the preset, if any is found!
}

byte isValidPreset(sfPresetHeader *preset) //Valid for playback?
{
	if (preset->wBank>128) return 0; //Invalid bank!
	if (preset->wPreset>127) return 0; //Invalid preset!
	return 1; //Valid preset!
}

//PBAG
byte getSFPresetBag(RIFFHEADER *sf,word wPresetBagNdx, sfPresetBag *result)
{
	return getRIFFData(sf->pbag,wPresetBagNdx,sizeof(sfPresetBag),result); //Give the preset Bag, if any is found!
}

//Next preset bag is just one index up.

byte isPresetBagNdx(RIFFHEADER *sf, uint_32 preset, word wPresetBagNdx)
{
	sfPresetHeader nextpreset, currentpreset;
	if (getSFPreset(sf,preset+1,&nextpreset) && getSFPreset(sf,preset,&currentpreset)) //Next&current preset found?
	{	
		return ((nextpreset.wPresetBagNdx>wPresetBagNdx) && (wPresetBagNdx>=currentpreset.wPresetBagNdx)); //Are we owned by the preset!
	}
	return 0; //Not our pbag!
}

//PMOD

byte getSFPresetMod(RIFFHEADER *sf, word wPresetModNdx, sfModList *result)
{
	return getRIFFData(sf->pmod,wPresetModNdx,sizeof(sfModList),result); //Give the preset Mod, if any is found!
}

byte isPresetModNdx(RIFFHEADER *sf, word preset, word wPresetBagNdx, word wModNdx)
{
	sfPresetBag currentpbag; //current!
	sfPresetBag nextpbag; //next!
	if (getSFPresetBag(sf,wPresetBagNdx,&currentpbag) && getSFPresetBag(sf,wPresetBagNdx+1,&nextpbag))
	{
		return ((nextpbag.wModNdx>wModNdx) && (wModNdx>=currentpbag.wModNdx)); //Are we owned by the preset bag!
	}
	return 0; //Not our pmod!
}

//PGEN

byte getSFPresetGen(RIFFHEADER *sf, word wPresetGenNdx, sfGenList *result)
{
	return getRIFFData(sf->pgen,wPresetGenNdx,sizeof(sfGenList),result); //Give the preset Mod, if any is found!
}

byte isPresetGenNdx(RIFFHEADER *sf, word preset, word wPresetBagNdx, word wGenNdx)
{
	sfPresetBag currentpbag; //current!
	sfPresetBag nextpbag; //next!
	if (getSFPresetBag(sf,wPresetBagNdx,&currentpbag) && getSFPresetBag(sf,wPresetBagNdx+1,&nextpbag))
	{
		return ((nextpbag.wGenNdx>wGenNdx) && (wGenNdx>=currentpbag.wGenNdx)); //Are we owned by the preset bag!
	}
	return 0; //Not our pgen!
}

//Next, we have the instrument layer!

//INST

byte getSFInstrument(RIFFHEADER *sf, word Instrument, sfInst *result)
{
	return getRIFFData(sf->inst,Instrument,sizeof(sfInst),result); //Give the Instrument, if any is found!
}

//IBAG

byte getSFInstrumentBag(RIFFHEADER *sf, word wInstBagNdx, sfInstBag *result)
{
	return getRIFFData(sf->ibag,wInstBagNdx,sizeof(sfInstBag),result); //Give the Instrument Bag, if any is found!	
}

byte isInstrumentBagNdx(RIFFHEADER *sf, word Instrument, word wInstBagNdx)
{
	sfInst currentinstrument; //current!
	sfInst nextinstrument; //next!
	if (getSFInstrument(sf,Instrument,&currentinstrument) && getSFInstrument(sf,Instrument+1,&nextinstrument))
	{
		return ((nextinstrument.wInstBagNdx>wInstBagNdx) && (wInstBagNdx>=currentinstrument.wInstBagNdx)); //Are we owned by the instrument!
	}
	return 0; //Not our pmod!
	
}

//IMOD

byte getSFInstrumentMod(RIFFHEADER *sf, word wInstrumentModNdx, sfModList *result)
{
	return getRIFFData(sf->imod,wInstrumentModNdx,sizeof(sfModList),result); //Give the preset Mod, if any is found!
}

byte isInstrumentModNdx(RIFFHEADER *sf, word Instrument, word wInstrumentBagNdx, word wInstrumentModNdx)
{
	sfInstBag currentibag; //current!
	sfInstBag nextibag; //next!
	if (getSFInstrumentBag(sf,wInstrumentBagNdx,&currentibag) && getSFInstrumentBag(sf,wInstrumentBagNdx+1,&nextibag))
	{
		return ((nextibag.wInstModNdx>wInstrumentModNdx) && (wInstrumentModNdx>=currentibag.wInstModNdx)); //Are we owned by the instrument bag!
	}
	return 0; //Not our pmod!
}

//IGEN

byte getSFInstrumentGen(RIFFHEADER *sf, word wInstGenNdx, sfInstGenList *result)
{
	return getRIFFData(sf->igen,wInstGenNdx,sizeof(sfInstGenList),result); //Give the instrument Gen, if any is found!
}

byte isInstrumentGenNdx(RIFFHEADER *sf, word Instrument, word wInstrumentBagNdx, word wInstrumentGenNdx)
{
	sfInstBag currentibag; //current!
	sfInstBag nextibag; //next!
	if (getSFInstrumentBag(sf,wInstrumentBagNdx,&currentibag) && getSFInstrumentBag(sf,wInstrumentBagNdx+1,&nextibag))
	{
		return ((nextibag.wInstGenNdx>wInstrumentGenNdx) && (wInstrumentGenNdx>=currentibag.wInstGenNdx)); //Are we owned by the instrument bag!
	}
	return 0; //Not our pmod!
}

//Sample information about the samples.

byte getSFSampleInformation(RIFFHEADER *sf, word Sample, sfSample *result)
{
	byte temp;
	RIFF_ENTRY shdr = sf->shdr; //Get the SHDR data!
	if (!shdr.voidentry)
	{
		return 0; //Error!
	}
	temp = getRIFFData(shdr,Sample,sizeof(sfSample),result); //Give the sample information, if any is found!	
	if (temp) //Found?
	{
		if (result->byOriginalPitch&0x80) //128+?
		{
			result->byOriginalPitch = 60; //Assume 60!
		}
	}
	return temp; //Give the result!
}

//Samples themselves!

short getsample16(word sample)
{
    return unsigned2signed16(sample); //Give the 16-bit sample!
}

short getsample24_16(uint_32 sample) //Get 24 bits sample and convert it to a 16-bit sample!
{
	/*union
	{
		uint_32 sample32;
		int_32 i;
	} u;
	u.sample32 = sample;
	if (u.sample32&0x800000) //Sign bit set?
	{
		u.sample32 |= 0xFF000000; //Sign extend!
	}
    return (short)((((float)u.i)/(float)0xFFFFFF)*(float)SHRT_MAX); //Give the 24-bit sample as a 16-bit sample, converted!
	*/

	union
	{
		uint_32 sample32;
		int_32 samplesigned;
	} u;
	u.sample32 = sample; //Load basic sample!
	if (u.sample32&0x800000) //Sign bit set?
	{
		u.sample32 |= 0xFF000000; //Sign extend!
	}

	//Now we have a 24-bit sample loaded!
	u.samplesigned >>= 8; //Convert to 16-bit sample range!
	return (short)u.samplesigned; //Convert to short for the result!
}

//Sample!
byte getSFsample(RIFFHEADER *sf, uint_32 sample, short *result) //Get a 16/24-bit(downsampled) sample!
{
	word sample16;
	byte gotsample16 = getRIFFData(sf->pcmdata,sample,sizeof(word),&sample16); //Get the sample!
	
	//24-bit sample high 8 bits
	byte sample24;
	byte gotsample24 = getRIFFData(sf->pcm24data,sample,sizeof(byte),&sample24); //Get the sample!
	
	//Take the correct sample (16/24 bit samples with conversion to 16-bit samples)
	if (gotsample24 && gotsample16) //24-bit sample found?
	{
		uint_32 tempsample;
		tempsample = sample24;
		tempsample <<=16;
		tempsample |= sample16; //Create the full sample!
		*result = getsample24_16(tempsample); //Get 24-bit sample!
		return 1; //OK!
	}
	else if (gotsample16) //16-bit sample found?
	{
		word fullsample16 = sample16; //Create the 16-bit sample!
		*result = getsample16(fullsample16); //Get the sample!
		return 1; //OK!
	}

	//Invalid sample?
	*result = 0; //Clear!
	return 0; //Invalid sample!
}

/*

Global zone detection

*/

byte isGlobalPresetZone(RIFFHEADER *sf, uint_32 preset, word PBag)
{
	sfPresetHeader currentpreset;
	sfPresetBag pbag;
	sfPresetBag pbag2;
	word firstPBag;
	sfGenList finalgen;
	if (getSFPreset(sf,preset,&currentpreset)) //Retrieve the header!
	{
		if (isValidPreset(&currentpreset)) //Valid preset?
		{
			firstPBag = currentpreset.wPresetBagNdx; //Load the first PBag!
			if (PBag==firstPBag) //Must be the first PBag!
			{
				if (isPresetBagNdx(sf,preset,firstPBag) && isPresetBagNdx(sf,preset,firstPBag+1)) //Multiple zones?
				{
					//Now lookup the final entry of the first PBag!
					if (getSFPresetBag(sf,firstPBag+1,&pbag)) //Load the second zone!
					{
						if (isPresetGenNdx(sf,preset,firstPBag,pbag.wGenNdx-1)) //Final is valid?
						{
							if (getSFPresetGen(sf,pbag.wGenNdx-1,&finalgen)) //Retrieve the final generator of the first zone! //Loaded!
							{
								if (finalgen.sfGenOper!=instrument) //Final isn't an instrument?
								{
									return 1; //We're a global zone!
								}
							}
						}
						
						if (getSFPresetBag(sf,firstPBag,&pbag2)) //First is valid?
						{
							if (!isPresetGenNdx(sf,preset,firstPBag,pbag2.wGenNdx) && isPresetModNdx(sf,preset,firstPBag,pbag2.wModNdx)) //No generators but do have modulators?
							{
								return 1; //We're a global zone after all!
							}
						}
					}
				}
			}
		}
	}
	return 0; //No global zone!
}

byte isGlobalInstrumentZone(RIFFHEADER *sf, word instrument, word IBag)
{
	sfInst currentinstrument;
	word firstIBag;
	sfInstBag ibag;
	sfInstGenList finalgen;
	sfInstBag ibag2;
	if (getSFInstrument(sf,instrument,&currentinstrument)) //Valid instrument?
	{
		firstIBag = currentinstrument.wInstBagNdx; //Load the first PBag!
		if (IBag==firstIBag) //Must be the first PBag!
		{
			if (isInstrumentBagNdx(sf,instrument,firstIBag) && isInstrumentBagNdx(sf,instrument,firstIBag+1)) //Multiple zones?
			{
				//Now lookup the final entry of the first PBag!
				if (getSFInstrumentBag(sf,firstIBag+1,&ibag)) //Load the second zone!
				{
					if (isInstrumentGenNdx(sf,instrument,firstIBag,ibag.wInstGenNdx-1)) //Final is valid?
					{
						if (getSFInstrumentGen(sf,ibag.wInstGenNdx-1,&finalgen)) //Retrieve the final generator of the first zone! //Loaded!
						{
							if (finalgen.sfGenOper!=sampleID) //Final isn't an instrument?
							{
								return 1; //We're a global zone!
							}
						}
					}
				}
				
				if (getSFInstrumentBag(sf,firstIBag,&ibag2)) //First is valid?
				{
					if (!isInstrumentGenNdx(sf,instrument,firstIBag,ibag2.wInstGenNdx) && isPresetModNdx(sf,instrument,firstIBag,ibag2.wInstModNdx)) //No generators but do have modulators?
					{
						return 1; //We're a global zone after all!
					}
				}
			}
		}
	}
	return 0; //No global zone!
}

byte isValidPresetZone(RIFFHEADER *sf, uint_32 preset, word PBag)
{
	sfPresetBag pbag;
	sfGenList finalgen;
	if (isGlobalPresetZone(sf,preset,PBag)) //Valid global zone?
	{
		return 1; //Global zone: no instrument is allowed!
	}
	
	//We're a local zone!
	
	//Now lookup the final entry of the first PBag!
	if (getSFPresetBag(sf,PBag+1,&pbag)) //Load the second zone!
	{
		if (isPresetGenNdx(sf,preset,PBag,pbag.wGenNdx-1)) //Final is valid?
		{
			if (getSFPresetGen(sf,pbag.wGenNdx-1,&finalgen)) //Retrieve the final generator of the first zone! //Loaded!
			{
				if (finalgen.sfGenOper!=instrument) //Final isn't an instrument?
				{
					return 0; //We're a local zone without an instrument!
				}
				return 1; //Valid: we have an instrument!
			}
		}
	}
	
	return 0; //Invalid zone!
}

byte isValidInstrumentZone(RIFFHEADER *sf, word instrument, word IBag)
{
	sfInstBag ibag;
	sfInstGenList finalgen;
	if (isGlobalInstrumentZone(sf,instrument,IBag)) //Valid global zone?
	{
		return 1; //Global zone: no sampleid is allowed!
	}
	
	//We're a local zone!
	
	//Now lookup the final entry of the first PBag!
	if (getSFInstrumentBag(sf,IBag+1,&ibag)) //Load the second zone!
	{
		if (isInstrumentGenNdx(sf,instrument,IBag,ibag.wInstGenNdx-1)) //Final is valid?
		{
			if (getSFInstrumentGen(sf,ibag.wInstGenNdx-1,&finalgen)) //Retrieve the final generator of the first zone! //Loaded!
			{
				if (finalgen.sfGenOper!=sampleID) //Final isn't a sampleid?
				{
					return 0; //We're a local zone without an instrument!
				}
				return 1; //Valid: we have an instrument!
			}
		}
	}
	
	return 0; //Invalid zone!
}

/*

Finally: some lookup functions for contents within the bags!

*/

byte lookupSFPresetMod(RIFFHEADER *sf, uint_32 preset, word PBag, SFModulator sfModSrcOper, sfModList *result)
{
	sfPresetHeader currentpreset;
	word CurrentMod;
	sfPresetBag pbag;
	sfModList mod;
	byte found;
	found = 0; //Default: not found!
	if (getSFPreset(sf,preset,&currentpreset)) //Retrieve the header!
	{
		if (isValidPreset(&currentpreset)) //Valid preset?
		{
			if (isPresetBagNdx(sf,preset,PBag)) //Process the PBag for our preset&pbag!
			{
				if (getSFPresetBag(sf,PBag,&pbag)) //Load the current PBag! //Valid?
				{
					if (isValidPresetZone(sf,preset,PBag)) //Valid?
					{
						CurrentMod = pbag.wModNdx; //Load the first PMod!
						for (;isPresetModNdx(sf,preset,PBag,CurrentMod);) //Process all PMods for our bag!
						{
							if (getSFPresetMod(sf,CurrentMod,&mod)) //Valid?
							{
								if (mod.sfModSrcOper==sfModSrcOper) //Found?
								{
									found = 1; //Found!
									memcpy(result,&mod,sizeof(*result)); //Set to last found!
								}
							}
							++CurrentMod;
						}
					}
				}
			}
		}
	}
	return found; //Not found or last found!
}

byte lookupSFPresetGen(RIFFHEADER *sf, uint_32 preset, word PBag, SFGenerator sfGenOper, sfGenList *result)
{
	sfPresetHeader currentpreset;
	word CurrentGen;
	sfPresetBag pbag;
	sfGenList gen;
	byte found;
	found = 0; //Default: not found!
	if (getSFPreset(sf,preset,&currentpreset)) //Retrieve the header!
	{
		if (isValidPreset(&currentpreset)) //Valid preset?
		{
			if (isPresetBagNdx(sf,preset,PBag)) //Process all PBags for our preset!
			{
				if (getSFPresetBag(sf,PBag,&pbag)) //Load the current PBag! //Valid?
				{
					if (isValidPresetZone(sf,preset,PBag)) //Valid?
					{
						CurrentGen = pbag.wGenNdx; //Load the first PGen!
						for (;isPresetGenNdx(sf,preset,PBag,CurrentGen);) //Process all PGens for our bag!
						{
							if (getSFPresetGen(sf,CurrentGen,&gen)) //Valid?
							{
								if (gen.sfGenOper==sfGenOper) //Found?
								{
									found = 1; //Found!
									memcpy(result,&gen,sizeof(*result)); //Set to last found!
								}
							}
							++CurrentGen;
						}
					}
				}
			}
		}
	}
	return found; //Not found or last found!
}



byte lookupSFInstrumentMod(RIFFHEADER *sf, word instrument, word IBag, SFModulator sfModSrcOper, sfModList *result)
{
	sfInst currentinstrument;
	word CurrentMod;
	sfInstBag ibag;
	sfModList mod;
	byte found;
	found = 0; //Default: not found!
	if (getSFInstrument(sf,instrument,&currentinstrument)) //Valid instrument?
	{
		if (isInstrumentBagNdx(sf,instrument,IBag)) //Process all PBags for our preset!
		{
			if (getSFInstrumentBag(sf,IBag,&ibag)) //Valid?
			{
				if (isValidInstrumentZone(sf,instrument,IBag)) //Valid?
				{
					CurrentMod = ibag.wInstModNdx; //Load the first PMod!
					for (;isInstrumentModNdx(sf,instrument,IBag,CurrentMod);) //Process all PMods for our bag!
					{
						if (getSFInstrumentMod(sf,CurrentMod,&mod)) //Valid?
						{
							if (mod.sfModSrcOper==sfModSrcOper) //Found?
							{
								found = 1;
								memcpy(result,&mod,sizeof(*result)); //Set to last found!
							}
						}
						++CurrentMod;
					}
				}
			}
		}
	}
	return found; //Not found or last found!
}

byte lookupSFInstrumentGen(RIFFHEADER *sf, word instrument, word IBag, SFGenerator sfGenOper, sfInstGenList *result)
{
	sfInst currentinstrument;
	word CurrentGen;
	sfInstBag ibag;
	sfInstGenList gen;
	uint_32 firstgen, keyrange, temp; //Other generators and temporary calculation!
	byte found;
	byte dontignoregenerators;
	found = 0;
	if (getSFInstrument(sf,instrument,&currentinstrument)) //Valid instrument?
	{
		if (isInstrumentBagNdx(sf,instrument,IBag)) //Process all PBags for our preset!
		{
			if (getSFInstrumentBag(sf,IBag,&ibag)) //Valid?
			{
				if (isValidInstrumentZone(sf,instrument,IBag)) //Valid?
				{
					CurrentGen = ibag.wInstGenNdx; //Load the first PMod!
					firstgen = CurrentGen; //Save first generator position!
					keyrange = 0; //We're resetting the first generator and key range to unspecified!
					dontignoregenerators = 1; //Default: don't ignore generators for this zone!
					for (;isInstrumentGenNdx(sf,instrument,IBag,CurrentGen);) //Process all PMods for our bag!
					{
						if (getSFInstrumentGen(sf,CurrentGen,&gen)) //Valid?
						{
							byte valid;
							valid = 1; //Default: still valid!
							if (gen.sfGenOper==keyRange) //KEY RANGE?
							{
								if (firstgen!=CurrentGen) //Not the first?
								{
									valid = 0; //Ignore this generator!
								}
								if (valid) //Valid?
								{
									keyrange = CurrentGen; //Save the position of the last key range generator!
									keyrange |= 0x10000; //Set flag: we're used!
								}
							}
							else if (gen.sfGenOper==velRange) //VELOCITY RANGE?
							{
								temp = CurrentGen; //Load!
								--temp; //Decrease!
								temp &= 0xFFFF; //16-bit range!
								temp |= 0x10000; //Set bit for lookup!
								if (keyrange!=temp) //Last wasn't a key range?
								{
									valid = 0; //Ignore this generator!
								}
							}
							if (valid) //Still valid?
							{
								if (gen.sfGenOper==sfGenOper && (dontignoregenerators || gen.sfGenOper==sampleID)) //Found and not ignoring (or sampleid generator)?
								{
									//Log the retrieval!
									found = 1; //Found!
									memcpy(result,&gen,sizeof(*result)); //Set to last found!
								}
								if (gen.sfGenOper==sampleID) //SAMPLEID?
								{
									dontignoregenerators = 0; //Ignore all generators after the SAMPLEID generator!
								}
							}
						}
						++CurrentGen;
					}
				}
			}
		}
	}
	return found; //Not found or last found!
}

byte lookupPresetByInstrument(RIFFHEADER *sf, word preset, word bank, uint_32 *result)
{
	uint_32 currentpreset;
	sfPresetHeader activepreset; //Current preset data!
	for (currentpreset=0;currentpreset<0xFFFFFFFF;) //Check for the correct preset!
	{
		if (getSFPreset(sf,currentpreset,&activepreset)) //Get the preset!
		{
			if (isValidPreset(&activepreset)) //Valid?
			{
				if (activepreset.wBank==bank) //Bank found?
				{
					if (activepreset.wPreset==preset) //Program/preset found?
					{
						break; //Stop searching!
					}
				}
			}
		}
		else //Not found?
		{
			break; //Stop searching: bank/preset not found!
		}
		++currentpreset; //Do next preset!
	}
	
	if (!isValidPreset(&activepreset)) //Not found?
	{
		return 0; //Invalid preset: disabled?
	}

	if (activepreset.wBank!=bank || activepreset.wPreset!=preset)
	{
		return 0; //Unfound preset: disabled!
	}
	
	*result = currentpreset; //Set the preset found!
	return 1; //We've found our preset!
}

byte lookupPBagByMIDIKey(RIFFHEADER *sf, uint_32 preset, byte MIDIKey, byte MIDIVelocity, word *result)
{
	word PBag; //Preset(instrument) bag!
	sfGenList pgen, pgen2;
	sfPresetHeader currentpreset;
	byte gotpgen;

	if (getSFPreset(sf,preset,&currentpreset)) //Found?
	{
		PBag = currentpreset.wPresetBagNdx; //Load the first preset bag!
		for (;isValidPresetZone(sf,preset,PBag);) //Valid zone?
		{
			if (!isGlobalPresetZone(sf,preset,PBag)) //Not a global zone?
			{
				gotpgen = lookupSFPresetGen(sf,preset,PBag,velRange,&pgen2); //Velocity lookup!
				if (lookupSFPresetGen(sf,preset,PBag,keyRange,&pgen)) //Key range lookup! //Found?
				{
					if (MIDIKey>=pgen.genAmount.ranges.byLo && MIDIKey<=pgen.genAmount.ranges.byHi) //Within range?
					{
						if (!gotpgen || (gotpgen && (MIDIVelocity>=pgen2.genAmount.ranges.byLo) && (MIDIVelocity<=pgen2.genAmount.ranges.byHi))) //Velocity match or no velocity?
						{
							*result = PBag; //It's this PBag!
							return 1; //Found!
						}
					}
					//No valid velocity/key!
				}
				else //Not found and not global(choosable)? By default it's the complete range!
				{
					*result = PBag; //It's this PBag!
					return 1; //Found!
				}
			}
			++PBag; //Next zone!
		}
	}
	return 0; //Not found!
}

byte lookupIBagByMIDIKey(RIFFHEADER *sf, word instrument, byte MIDIKey, byte MIDIVelocity, word *result, byte RequireInstrument)
{
	word IBag; //Instrument(note) bag!
	sfInstGenList igen, igen2;
	sfInst currentinstrument;
	byte gotigen;
	byte exists;

	if (getSFInstrument(sf,instrument,&currentinstrument)) //Found?
	{
		IBag = currentinstrument.wInstBagNdx; //Load the first preset bag!
		for (;isValidInstrumentZone(sf,instrument,IBag);) //Valid zone?
		{
			if (!isGlobalInstrumentZone(sf,instrument,IBag))
			{
				//Sample lookup/verification!
				sfSample sample;
				sfInstGenList sampleid;
				//Valid?
				exists = lookupSFInstrumentGen(sf,instrument,IBag,keyRange,&igen); //Key range lookup!
				if (exists) //Key range found?
				{
					exists = ((MIDIKey>=igen.genAmount.ranges.byLo) && (MIDIKey<=igen.genAmount.ranges.byHi));
				}
				if (!exists) //Invalid? Look further!
				{
					exists = lookupSFInstrumentGen(sf,instrument,IBag,keynum,&igen); //Key number lookup!
					if (exists) //Valid?
					{
						exists = (igen.genAmount.wAmount==MIDIKey); //Does it exist?
					}
				}
				if (exists)
				{
					exists = !RequireInstrument; //Default: invalid when instrument is required!
					if (lookupSFInstrumentGen(sf,instrument,IBag,sampleID,&sampleid)) //SAMPLEID found?
					{
						exists |= getSFSampleInformation(sf,sampleid.genAmount.wAmount,&sample); //Sample found=Valid!						
					}
					if (exists) //Valid IGEN?
					{
						gotigen = lookupSFInstrumentGen(sf,instrument,IBag,velocity,&igen2); //Velocity lookup!
						if (!gotigen) //No velocity filter? Take just the key filter!
						{
							*result = IBag; //It's this PBag!
							return 1; //Found!
						}
						else if (igen2.genAmount.wAmount==MIDIVelocity) //Gotten a velocity filter?
						{
							*result = IBag; //It's this PBag!
							return 1; //Found!
						}
					}
					//No valid velocity/key/sampleid!
				}
			}
			++IBag; //Next zone!
		}
	}
	return 0; //Not found!
}

//Global lookup support for supported entries!

byte lookupSFPresetModGlobal(RIFFHEADER *sf, uint_32 preset, word PBag, SFModulator sfModSrcOper, sfModList *result)
{
	sfPresetHeader currentpreset;
	word GlobalPBag;
	if (lookupSFPresetMod(sf,preset,PBag,sfModSrcOper,result)) //Found normally?
	{
		return 1; //Found normally!
	}
	if (getSFPreset(sf,preset,&currentpreset)) //Found?
	{
		GlobalPBag = currentpreset.wPresetBagNdx; //Load the first preset bag!
		if (isValidPresetZone(sf,preset,GlobalPBag)) //Valid zone?
		{
			if (isGlobalPresetZone(sf,preset,GlobalPBag)) //Global zone?
			{
				if (lookupSFPresetMod(sf,preset,GlobalPBag,sfModSrcOper,result)) //Global found?
				{
					return 1; //Global found!
				}
			}
		}
	}
	return 0; //Not found at all!
}

byte lookupSFPresetGenGlobal(RIFFHEADER *sf, word preset, word PBag, SFGenerator sfGenOper, sfGenList *result)
{
	sfPresetHeader currentpreset;
	word GlobalPBag;
	if (lookupSFPresetGen(sf,preset,PBag,sfGenOper,result)) //Found normally?
	{
		return 1; //Found normally!
	}
	if (getSFPreset(sf,preset,&currentpreset)) //Found?
	{
		GlobalPBag = currentpreset.wPresetBagNdx; //Load the first preset bag!
		if (isValidPresetZone(sf,preset,GlobalPBag)) //Valid zone?
		{
			if (isGlobalPresetZone(sf,preset,GlobalPBag)) //Global zone?
			{
				if (lookupSFPresetGen(sf,preset,GlobalPBag,sfGenOper,result)) //Global found?
				{
					return 1; //Global found!
				}
			}
		}
	}
	return 0; //Not found at all!
}

byte lookupSFInstrumentModGlobal(RIFFHEADER *sf, uint_32 instrument, word IBag, SFModulator sfModSrcOper, sfModList *result)
{
	sfInst currentinstrument;
	word GlobalIBag;
	if (lookupSFInstrumentMod(sf,instrument,IBag,sfModSrcOper,result)) //Found normally?
	{
		return 1; //Found normally!
	}
	if (getSFInstrument(sf,instrument,&currentinstrument)) //Found?
	{
		GlobalIBag = currentinstrument.wInstBagNdx; //Load the first preset bag!
		if (isValidPresetZone(sf,instrument,GlobalIBag)) //Valid zone?
		{
			if (isGlobalPresetZone(sf,instrument,GlobalIBag)) //Global zone?
			{
				if (lookupSFInstrumentMod(sf,instrument,GlobalIBag,sfModSrcOper,result)) //Global found?
				{
					return 1; //Global found!
				}
			}
		}
	}
	return 0; //Not found at all!
}

byte lookupSFInstrumentGenGlobal(RIFFHEADER *sf, word instrument, word IBag, SFGenerator sfGenOper, sfInstGenList *result)
{
	sfInst currentinstrument;
	word GlobalIBag;
	if (lookupSFInstrumentGen(sf,instrument,IBag,sfGenOper,result)) //Found normally?
	{
		return 1; //Found normally!
	}
	if (getSFInstrument(sf,instrument,&currentinstrument)) //Found?
	{
		GlobalIBag = currentinstrument.wInstBagNdx; //Load the first preset bag!
		if (isValidInstrumentZone(sf,instrument,GlobalIBag)) //Valid zone?
		{
			if (isGlobalInstrumentZone(sf,instrument,GlobalIBag)) //Global zone?
			{
				if (lookupSFInstrumentGen(sf,instrument,GlobalIBag,sfGenOper,result)) //Global found?
				{
					return 1; //Global found!
				}
			}
		}
	}
	return 0; //Not found at all!
}