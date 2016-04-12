#include "headers/types.h" //Basic type support!
#include "headers/hardware/ports.h" //Basic PORT compatibility!
#include "headers/hardware/vga/vga.h" //VGA data!
#include "headers/mmu/mmu.h" //For CPU passtrough!
#include "headers/hardware/vga/vga_crtcontroller.h" //CRT controller!
#include "headers/support/log.h" //Logging support for debugging this!
#include "headers/hardware/vga/vga_sequencer.h" //Sequencer support for special actions!
#include "headers/support/zalloc.h" //Zero allocation (memprotect) support!
#include "headers/hardware/vga/vga_vram.h" //VRAM support!
#include "headers/hardware/vga/vga_cga_mda.h" //CGA/MDA support for it's display memory!

//VGA.VRAM is a pointer to the start of the VGA VRAM (256K large)

//COLOR MODES:
//VGA: 2, 3 (B/W/Bold), 4, 4 shades, 16, 256
//SVGA: 32k, 64k, True Colors

//We handle all input for writing to VRAM (CPU interrupts) and reading from VRAM (hardware) here!

//Bit from left to right starts with 0(value 128) ends with 7(value 1)

//Below patches input addresses for rendering only.
OPTINLINE word patch_map1314(VGA_Type *VGA, word addresscounter) //Patch full VRAM address!
{ //Check this!
	word memoryaddress = addresscounter; //New row scan to use!
	SEQ_DATA *Sequencer;
	Sequencer = (SEQ_DATA *)VGA->Sequencer; //The sequencer!

	word rowscancounter = Sequencer->rowscancounter; //The row scan counter we use!

	register word bit; //Load row scan counter!
	if (!VGA->registers->CRTControllerRegisters.REGISTERS.CRTCMODECONTROLREGISTER.MAP13) //a13=Bit 0 of the row scan counter!
	{
		//Row scan counter bit 1 is placed on the memory bus bit 14 during active display time.
		//Bit 1, placed on memory address bit 14 has the effect of quartering the memory.
		bit = rowscancounter; //Current row scan counter!
		bit &= 1; //Bit0 only!
		bit <<= 13; //Shift to our position (bit 13)!
		memoryaddress &= 0xDFFF; //Clear bit13!
		memoryaddress |= bit; //Set bit13 if needed!
	}

	if (!VGA->registers->CRTControllerRegisters.REGISTERS.CRTCMODECONTROLREGISTER.MAP14) //a14<=Bit 1 of the row scan counter!
	{
		bit = rowscancounter; //Current row scan counter!
		bit &= 2; //Bit1 only!
		bit <<= 13; //Shift to our position (bit 14)!
		memoryaddress &= 0xBFFF; //Clear bit14;
		memoryaddress |= bit; //Set bit14 if needed!
	}
	
	return memoryaddress; //Give the linear address!
}

OPTINLINE word addresswrap(VGA_Type *VGA, word memoryaddress) //Wraps memory arround 64k!
{
	register word address2; //Load the initial value for calculating!
	register word result;
	register byte temp;
	if (VGA->precalcs.BWDModeShift == 1) //Word mode?
	{
		result = memoryaddress; //Default: don't change!
		address2 = memoryaddress; //Load the address for calculating!
		temp = 0xD; //Load default location (13)
		temp |= (VGA->registers->CRTControllerRegisters.REGISTERS.CRTCMODECONTROLREGISTER.AW << 1); //MA15 instead of MA13 when set!
		address2 >>= temp; //Apply MA15/MA13 to bit 0!
		address2 &= 1; //Only load bit 0!
		result &= 0xFFFE; //Clear bit 0!
		result |= address2; //Add bit MA15/MA13 at bit 0!
		return result; //Give the result!
	}
	return memoryaddress; //Original address!
}

OPTINLINE word applyCGAMDAWrap(VGA_Type *VGA, word offset)
{
	if (CGAEMULATION_ENABLED(VGA)) //CGA emulation enabled? Quarter the memory installed!
	{
		offset &= 0xFFFF; //Apply CGA memory!
	}
	else if (MDAEMULATION_ENABLED(VGA)) //MDA emulation enabled? Quarter the memory installed more!
	{
		offset &= 0x3FFF; //Apply MDA memory!
	}
	return offset; //Give the calculated offset!
}

//Planar access to VRAM
byte readVRAMplane(VGA_Type *VGA, byte plane, word offset, byte mode) //Read from a VRAM plane!
{
	if (!VGA) return 0; //Invalid VGA!
	if (!VGA->VRAM_size) return 0; //No size!
	uint_32 fulloffset2;

	if (mode&1) offset = addresswrap(VGA,offset); //Apply address wrap?
	if (mode&0x80) offset = patch_map1314(VGA, offset); //Patch MAP13&14!

	fulloffset2 = applyCGAMDAWrap(VGA,offset); //Apply wrapping according to the device!

	plane &= 3; //Only 4 planes are available! Wrap arround the planes if needed!

	if (CGAMDAEMULATION_ENABLED(VGA) && (plane&2)) return 0; //High planes on the CGA don't exist!

	fulloffset2 = offset; //Default offset to use!
	fulloffset2 <<= 2; //We cycle through the offsets!
	fulloffset2 |= plane; //The plane goes from low to high, through all indexes!

	fulloffset2 &= 0x3FFFF; //Wrap arround memory! Maximum of 256K memory!

	if (!VGA->registers->SequencerRegisters.REGISTERS.SEQUENCERMEMORYMODEREGISTER.ExtendedMemory) fulloffset2 &= 0xFFFF; //Only 64K memory available, so wrap arround it!

	if (fulloffset2<VGA->VRAM_size) //VRAM valid, simple check?
	{
		return VGA->VRAM[fulloffset2]; //Read the data from VRAM!
	}
	return 0; //Nothing there: invalid VRAM!
}

void writeVRAMplane(VGA_Type *VGA, byte plane, word offset, byte value, byte mode) //Write to a VRAM plane!
{
	if (!VGA) return; //Invalid VGA!
	if (!VGA->VRAM_size) return; //No size!
	
	if (mode & 1) offset = addresswrap(VGA, offset); //Apply address wrap?
	if (mode & 0x80) offset = patch_map1314(VGA, offset); //Patch MAP13&14!

	offset = applyCGAMDAWrap(VGA,offset); //Apply wrapping according to the device!

	plane &= 3; //Only 4 planes are available!

	register uint_32 fulloffset2;
	fulloffset2 = offset; //Load the offset!
	fulloffset2 <<= 2; //We cycle through the offsets!
	fulloffset2 |= plane; //The plane goes from low to high, through all indexes!

	fulloffset2 &= 0x3FFFF; //Wrap arround memory!

	if (!VGA->registers->SequencerRegisters.REGISTERS.SEQUENCERMEMORYMODEREGISTER.ExtendedMemory) fulloffset2 &= 0xFFFF; //Only 64K memory available, so wrap arround it!

	if (fulloffset2<VGA->VRAM_size) //VRAM valid, simple check?
	{
		VGA->VRAM[fulloffset2] = value; //Set the data in VRAM!
		if (plane==2) //Character RAM updated?
		{
			VGA_plane2updated(VGA,offset); //Plane 2 has been updated!	
		}
	}
}