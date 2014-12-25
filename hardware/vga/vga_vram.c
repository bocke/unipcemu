#include "headers/types.h" //Basic type support!
#include "headers/hardware/ports.h" //Basic PORT compatibility!
#include "headers/hardware/vga.h" //VGA data!
#include "headers/mmu/mmu.h" //For CPU passtrough!
#include "headers/hardware/vga_rest/textmodedata.h" //Text mode data for loading!
#include "headers/hardware/vga_rest/colorconversion.h" //Color conversion support!
#include "headers/hardware/vga_screen/vga_crtcontroller.h" //CRT controller!
#include "headers/support/log.h" //Logging support for debugging this!
#include "headers/hardware/vga_screen/vga_sequencer.h" //Sequencer support for special actions!
#include "headers/support/zalloc.h" //Zero allocation (memprotect) support!

//VGA.VRAM is a pointer to the start of the VGA VRAM (256K large)

//COLOR MODES:
//VGA: 2, 3 (B/W/Bold), 4, 4 shades, 16, 256
//SVGA: 32k, 64k, True Colors

//We handle all input for writing to VRAM (CPU interrupts) and reading from VRAM (hardware) here!

//is_renderer determines special stuff for the renderer:
//bit 1 contains the "I'm a renderer" flag.
//bit 2 contains enable the first buffer for this block of 4 bytes memory.
//bit 3 contains enable the second buffer for this block of 4 bytes memory.

byte LOG_VRAM_WRITES = 0;

//Below patches input addresses for rendering only.
static OPTINLINE word patch_map1314(VGA_Type *VGA, word rowscanaddress) //Patch full VRAM address!
{ //Check this!
	word newrowscan = rowscanaddress; //New row scan to use!
	SEQ_DATA *Sequencer;
	Sequencer = (SEQ_DATA *)VGA->Sequencer; //The sequencer!
	
	register uint_32 bit; //Load row scan counter!
	if (!VGA->registers->CRTControllerRegisters.REGISTERS.CRTCMODECONTROLREGISTER.MAP13) //a13=Bit 0 of the row scan counter!
	{
		//Row scan counter bit 1 is placed on the memory bus bit 14 during active display time.
		//Bit 1, placed on memory address bit 14 has the effect of quartering the memory.
		newrowscan &= 0xDFFF; //Clear bit13!
		bit = Sequencer->Scanline; //Load the row scan counter!
		bit &= 1; //Bit0 only!
		bit <<= 13; //Shift to our position!
		newrowscan |= bit;
	}

	if (!VGA->registers->CRTControllerRegisters.REGISTERS.CRTCMODECONTROLREGISTER.MAP14) //a14<=Bit 1 of the row scan counter!
	{
		newrowscan &= 0xBFFF; //Clear bit14;
		bit = Sequencer->Scanline; //Load the row scan counter!
		bit &= 2; //Bit1 only!
		bit <<= 13; //Shift to our position!
		newrowscan |= bit;
	}
	
	return newrowscan; //Give the linear address!
}

static OPTINLINE word addresswrap(VGA_Type *VGA, word memoryaddress) //Wraps memory arround 64k!
{
	/*if (getVRAMMemAddrSize(VGA)==2) //Word address mode?
	{
		register word address = memoryaddress; //Init address to memory address!
		address &= ~1; //Clear MA0!
		if (VGA->registers->CRTControllerRegisters.REGISTERS.CRTCMODECONTROLREGISTER.AW) //MA15 has to be on MA0
		{
			address |= (address&0x8000)>>15; //Add bit MA15!
		}
		else //MA13 has to be on MA0?
		{
			address |= (address&0x2000)>>13; //Add bit MA13!
		}
		return address; //Adjusted address!
	}*/

	
	return memoryaddress; //Normal operating mode!
}


//Planar access to VRAM
byte readVRAMplane(VGA_Type *VGA, byte plane, word offset, byte is_renderer) //Read from a VRAM plane!
{
	if (!VGA) return 0; //Invalid VGA!
	if (!VGA->VRAM_size) return 0; //No size!
	word patchedoffset = offset; //Default offset to use!

	if (is_renderer) //First address wrap, next map13&14!
	{
		patchedoffset = addresswrap(VGA,offset); //Wrap!
		patchedoffset = patch_map1314(VGA,patchedoffset); //Patch MAP13&14!
	}

	register uint_32 fulloffset2;
	fulloffset2 = plane; //Load full plane!
	fulloffset2 <<= 16; //Move to the start of the plane!
	fulloffset2 |= patchedoffset; //Generate full offset!

	byte *data = &VGA->VRAM[SAFEMODUINT32(fulloffset2,VGA->VRAM_size)]; //Give the data!
	if (memprotect(data,sizeof(*data),"VGA_VRAM")) //VRAM valid?
	{
		return *data; //Read the data from VRAM!
	}
	return 0; //Nothing there: invalid VRAM!
}

void writeVRAMplane(VGA_Type *VGA, byte plane, uint_32 offset, byte value) //Write to a VRAM plane!
{
	if (!VGA) return; //Invalid VGA!
	if (!VGA->VRAM_size) return; //No size!

	register uint_32 fulloffset2;
	fulloffset2 = plane; //Load full plane!
	fulloffset2 <<= 16; //Move to the start of the plane!
	fulloffset2 |= offset; //Generate full offset!

	/*if (LOG_VRAM_WRITES) //Log where we write!
	{
		dolog("VRAM","Writing %i:%08X=%02X=%c",plane,offset,value,value); //Log it!
	}*/
	
	byte *data = &VGA->VRAM[SAFEMODUINT32(fulloffset2,VGA->VRAM_size)];

	if (memprotect(data,sizeof(*data),"VGA_VRAM"))
	{
		*data = value; //Set the data in VRAM!
		if (plane==2) //Character RAM updated?
		{
			VGA_plane2updated(VGA,offset); //Plane 2 has been updated!	
		}
	}
}

//Bit from left to right starts with 0(value 128) ends with 7(value 1)

byte getBitPlaneBit(VGA_Type *VGA, int plane, uint_32 offset, byte bit, byte is_renderer)
{
	byte bits;
	bits = readVRAMplane(VGA,plane,offset,is_renderer); //Get original bits!
	return GETBIT(bits,7-bit); //Give the bit!
}

void setBitPlaneBit(VGA_Type *VGA, int plane, uint_32 offset, byte bit, byte on) //For testing only. Read-Modify-Write!
{
	byte bits;
	bits = readVRAMplane(VGA,plane,offset,0); //Get original bits!
	if (on) //To turn bit on?
	{
		bits = SETBIT1(bits,7-bit); //Turn bit on!
	}
	else //To turn bit off?
	{
		bits = SETBIT0(bits,7-bit); //Turn bit off!
	}
	writeVRAMplane(VGA,plane,offset,bits); //Write the modified value back!
}

//END OF VGA COLOR SUPPORT!

//SVGA color support

/*
union
{
	struct
	{
		union
		{
			struct
			{
				byte datalow;
				byte datahigh;
			};
			word data;
		};
	};
	struct
	{
		byte b : 5;
		byte g : 5;
		byte r : 5;
		byte u : 1;
	};
} decoder32k; //32K decoder!

/
32k colors: 1:5:5:5
/

uint_32 MEMGRAPHICS_get32kcolors(uint_32 startaddr, int x, int y)
{
	uint_32 pixelnumber;
	pixelnumber = startaddr+((y*xres)*2)+(x*2); //Starting pixel!
	decoder32k.datahigh = VRAM_readdirect(pixelnumber+1);
	decoder32k.datalow = VRAM_readdirect(pixelnumber);
	return getcolX(decoder32k.r,decoder32k.g,decoder32k.b,0x1F); //Give RGB!
}

void MEMGRAPHICS_put32kcolors(uint_32 startaddr, int x, int y, word color)
{
	uint_32 pixelnumber;
	pixelnumber = startaddr+((y*xres)*2)+(x*2); //Starting pixel!
	VRAM_writedirect(pixelnumber,(color&0xFF)); //Low
	VRAM_writedirect(pixelnumber+1,((color>>8)&0xFF)); //High!
}

union
{
	struct
	{
		union
		{
			struct
			{
				byte datalow;
				byte datahigh;
			};
			word data;
		};
	};
	struct
	{
		byte b : 5;
		byte g : 6;
		byte r : 5;
	};
} decoder64k; //64K decoder!


/
64k colors: 5:6:5
/

uint_32 MEMGRAPHICS_get64kcolors(uint_32 startaddr, int x, int y)
{
	uint_32 pixelnumber;
	pixelnumber = startaddr+((y*xres)*2)+(x*2); //Starting pixel!
	decoder64k.datahigh = VRAM_readdirect(pixelnumber+1);
	decoder64k.datalow = VRAM_readdirect(pixelnumber);
	return getcol64k(decoder32k.r,decoder32k.g,decoder32k.b); //Give RGB!
}

void MEMGRAPHICS_put64kcolors(uint_32 startaddr, int x, int y, word color)
{
	uint_32 pixelnumber;
	pixelnumber = startaddr+((y*xres)*2)+(x*2); //Starting pixel!
	VRAM_writedirect(pixelnumber,(color&0xFF)); //Low
	VRAM_writedirect(pixelnumber+1,((color>>8)&0xFF)); //High!
}


/
24 bits true color 8:8:8
/

uint_32 MEMGRAPHICS_getTruecolors(uint_32 startaddr, int x, int y)
{
	uint_32 pixelnumber;
	pixelnumber = startaddr+((y*xres)*3)+(x*3); //Starting pixel!
	return RGB(VRAM_readdirect(pixelnumber),VRAM_readdirect(pixelnumber+1),VRAM_readdirect(pixelnumber+2));
}

void MEMGRAPHICS_putTruecolors(uint_32 startaddr, int x, int y, uint_32 color)
{
	uint_32 pixelnumber;
	pixelnumber = startaddr+((y*xres)*3)+(x*3); //Starting pixel!
	VRAM_writedirect(pixelnumber,(color&0xFF)); //R
	VRAM_writedirect(pixelnumber+1,((color>>8)&0xFF)); //G
	VRAM_writedirect(pixelnumber+2,((color>>16)&0xFF)); //B
}*/