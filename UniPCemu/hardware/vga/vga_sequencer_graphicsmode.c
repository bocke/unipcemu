/*

Copyright (C) 2019  Superfury

This file is part of UniPCemu.

UniPCemu is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

UniPCemu is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with UniPCemu.  If not, see <https://www.gnu.org/licenses/>.
*/

#define VGA_SEQUENCER_GRAPHICSMODE

#include "headers/types.h" //Basic types!
#include "headers/hardware/vga/vga.h" //VGA!
#include "headers/hardware/vga/vga_sequencer_graphicsmode.h" //Graphics mode!

extern LOADEDPLANESCONTAINER loadedplanes; //All read planes for the current processing!
byte pixelbuffer[8]; //All 8 pixels decoded from the planesbuffer!

/*

256 COLOR MODE

*/

void load256colorshiftmode() //256-color shift mode!
{
	INLINEREGISTER byte data;
	//Now all planes are loaded for our calculation!
	data = loadedplanes.splitplanes[0]; //First plane!
	pixelbuffer[1] = (data & 0xF); //Take second pixel!
	data >>= 4; //Shift high to low libble!
	pixelbuffer[0] = data; //Take first pixel!

	data = loadedplanes.splitplanes[1]; //Second plane!
	pixelbuffer[3] = (data & 0xF); //Take second pixel!
	data >>= 4; //Shift high to low libble!
	pixelbuffer[2] = data; //Take first pixel!

	data = loadedplanes.splitplanes[2]; //Third plane!
	pixelbuffer[5] = (data & 0xF); //Take second pixel!
	data >>= 4; //Shift high to low libble!
	pixelbuffer[4] = data; //Take first pixel!

	data = loadedplanes.splitplanes[3]; //Fourth plane!
	pixelbuffer[7] = (data & 0xF); //Take second pixel!
	data >>= 4; //Shift high to low libble!
	pixelbuffer[6] = data; //Take first pixel!
}

/*

SHIFT REGISTER INTERLEAVE MODE

*/

void loadpackedshiftmode() //Packed shift mode!
{
	INLINEREGISTER byte temp, tempbuffer; //A buffer for our current pixel!
	pixelbuffer[0] = pixelbuffer[1] = pixelbuffer[2] = pixelbuffer[3] = loadedplanes.splitplanes[2]; //Load high plane!
	pixelbuffer[4] = pixelbuffer[5] = pixelbuffer[6] = pixelbuffer[7] = loadedplanes.splitplanes[3]; //Load high plane!
	pixelbuffer[0] >>= 4;
	pixelbuffer[1] >>= 2;
	pixelbuffer[3] <<= 2; //Shift to the high part!
	pixelbuffer[4] >>= 4;
	pixelbuffer[5] >>= 2;
	pixelbuffer[7] <<= 2; //Shift to the high part!

	pixelbuffer[0] &= 0xC;
	pixelbuffer[1] &= 0xC;
	pixelbuffer[2] &= 0xC;
	pixelbuffer[3] &= 0xC;
	pixelbuffer[4] &= 0xC;
	pixelbuffer[5] &= 0xC;
	pixelbuffer[6] &= 0xC;
	pixelbuffer[7] &= 0xC; //Clear bits 0-1 and 4+!

	//First byte!
	tempbuffer = temp = loadedplanes.splitplanes[0]; //Load low plane!
	tempbuffer &= 3;
	pixelbuffer[3] |= tempbuffer;
	tempbuffer = (temp >>= 2); //Shift to the next data!
	tempbuffer &= 3;
	pixelbuffer[2] |= tempbuffer;
	tempbuffer = (temp >>= 2); //Shift to the next data!
	tempbuffer &= 3;
	pixelbuffer[1] |= tempbuffer;
	temp >>= 2; //Shift to the next data!
	tempbuffer &= 3;
	pixelbuffer[0] |= temp;

	//Second byte!
	tempbuffer = temp = loadedplanes.splitplanes[1]; //Load low plane!
	tempbuffer &= 3;
	pixelbuffer[7] |= tempbuffer;
	tempbuffer = (temp >>= 2); //Shift to the next data!
	tempbuffer &= 3;
	pixelbuffer[6] |= tempbuffer;
	tempbuffer = (temp >>= 2); //Shift to the next data!
	tempbuffer &= 3;
	pixelbuffer[5] |= tempbuffer;
	temp >>= 2; //Shift to the next data!
	tempbuffer &= 3;
	pixelbuffer[4] |= temp;
}

/*

SINGLE SHIFT MODE

*/

void loadplanarshiftmode() //Planar shift mode!
{
	INLINEREGISTER uint_32 originalplanes; //The loaded planes!
	INLINEREGISTER LOADEDPLANESCONTAINER currentplanes; //For splitting the planes!
	originalplanes = loadedplanes.loadedplanes; //Load the planes for retrieving!

	currentplanes.loadedplanes = originalplanes&0x01010101; //Load the value to split!
	pixelbuffer[7] = (currentplanes.plane0)|(currentplanes.plane1<<1)|(currentplanes.plane2<<2)|(currentplanes.plane3<<3); //Combine the four planes into a pixel!
	originalplanes >>= 1; //Shift to the next pixel!

	currentplanes.loadedplanes = originalplanes&0x01010101; //Load the value to split!
	pixelbuffer[6] = (currentplanes.plane0) | (currentplanes.plane1 << 1) | (currentplanes.plane2 << 2) | (currentplanes.plane3 << 3); //Combine the four planes into a pixel!
	originalplanes >>= 1; //Shift to the next pixel!

	currentplanes.loadedplanes = originalplanes&0x01010101; //Load the value to split!
	pixelbuffer[5] = (currentplanes.plane0) | (currentplanes.plane1 << 1) | (currentplanes.plane2 << 2) | (currentplanes.plane3 << 3); //Combine the four planes into a pixel!
	originalplanes >>= 1; //Shift to the next pixel!

	currentplanes.loadedplanes = originalplanes&0x01010101; //Load the value to split!
	pixelbuffer[4] = (currentplanes.plane0) | (currentplanes.plane1 << 1) | (currentplanes.plane2 << 2) | (currentplanes.plane3 << 3); //Combine the four planes into a pixel!
	originalplanes >>= 1; //Shift to the next pixel!

	currentplanes.loadedplanes = originalplanes&0x01010101; //Load the value to split!
	pixelbuffer[3] = (currentplanes.plane0) | (currentplanes.plane1 << 1) | (currentplanes.plane2 << 2) | (currentplanes.plane3 << 3); //Combine the four planes into a pixel!
	originalplanes >>= 1; //Shift to the next pixel!

	currentplanes.loadedplanes = originalplanes&0x01010101; //Load the value to split!
	pixelbuffer[2] = (currentplanes.plane0) | (currentplanes.plane1 << 1) | (currentplanes.plane2 << 2) | (currentplanes.plane3 << 3); //Combine the four planes into a pixel!
	originalplanes >>= 1; //Shift to the next pixel!

	currentplanes.loadedplanes = originalplanes&0x01010101; //Load the value to split!
	pixelbuffer[1] = (currentplanes.plane0) | (currentplanes.plane1 << 1) | (currentplanes.plane2 << 2) | (currentplanes.plane3 << 3); //Combine the four planes into a pixel!
	originalplanes >>= 1; //Shift to the next pixel!

	currentplanes.loadedplanes = originalplanes&0x01010101; //Load the value to split!
	pixelbuffer[0] = (currentplanes.plane0) | (currentplanes.plane1 << 1) | (currentplanes.plane2 << 2) | (currentplanes.plane3 << 3); //Combine the four planes into a pixel!
}

//Shiftregister: 2=ShiftRegisterInterleave, 1=Color256ShiftMode. Priority list: 1, 2, 0; So 1&3=256colorshiftmode, 2=ShiftRegisterInterleave, 0=SingleShift.
//When index0(VGA->registers->GraphicsRegisters.REGISTERS.MISCGRAPHICSREGISTER.AlphaNumericModeDisable)=1, getColorPlanesAlphaNumeric
//When index1(IGNOREATTRPLANES)=1, getColorPlanesIgnoreAttrPlanes

//http://www.openwatcom.org/index.php/VGA_Fundamentals:
//Packed Pixel: Color 256 Shift Mode.
//Parallel Planes: Else case!
//Interleaved: Shift Register Interleave!

/*

Core functions!

*/

static Handler loadpixel_jmptbl[4] = {
	loadplanarshiftmode,
	loadpackedshiftmode,
	load256colorshiftmode, //Normal VGA 256-color shift mode. Also with 8-bit DAC used(SVGA mode 2h)!
	loadplanarshiftmode //Normal 256-color shift mode. Also with 16-bit DAC used(SVGA mode 3h)!
}; //All the getpixel functionality!

Handler decodegraphicspixels = loadplanarshiftmode; //Active graphics mode!

void updateVGAGraphics_Mode(VGA_Type *VGA)
{
	decodegraphicspixels = loadpixel_jmptbl[VGA->precalcs.GraphicsModeRegister_ShiftRegister|VGA->precalcs.AttributeController_16bitDAC]; //Apply the current mode(with 8/16-bit support)!
}

void VGA_GraphicsDecoder(VGA_Type *VGA, word loadedlocation) //Graphics decoder!
{
	decodegraphicspixels(); //Split the pixels from the buffer!
	((SEQ_DATA *)VGA->Sequencer)->graphicsx = &pixelbuffer[0]; //Start rendering from the graphics buffer pixels at the current location!
}

void VGA_Sequencer_GraphicsMode(VGA_Type *VGA, SEQ_DATA *Sequencer, VGA_AttributeInfo *attributeinfo)
{
	attributeinfo->attribute = ((*Sequencer->graphicsx++)<<VGA_SEQUENCER_ATTRIBUTESHIFT); //Give the current pixel, loaded with our block!
	attributeinfo->fontpixel = 1; //Graphics attribute is always foreground by default!
}