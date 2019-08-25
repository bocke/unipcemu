/*
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

#ifndef TSENG_H
#define TSENG_H

#include "headers/types.h" //Basic types!
#include "headers/hardware/vga/vga.h" //Basic VGA!

typedef struct {
	byte extensionsEnabled;
	byte oldextensionsEnabled; //Old extensions status for detecting changes!

// Stored exact values of some registers. Documentation only specifies some bits but hardware checks may
// expect other bits to be preserved.
	//ET4K registers
	byte store_et4k_3d4_31;
	byte store_et4k_3d4_32;
	byte store_et4k_3d4_33;
	byte store_et4k_3d4_34;
	byte store_et4k_3d4_35;
	byte store_et4k_3d4_36;
	byte store_et4k_3d4_37;
	byte store_et4k_3d4_3f;

	//ET3K registers
	byte store_et3k_3d4_1b;
	byte store_et3k_3d4_1c;
	byte store_et3k_3d4_1d;
	byte store_et3k_3d4_1e;
	byte store_et3k_3d4_1f;
	byte store_et3k_3d4_20;
	byte store_et3k_3d4_21;
	byte store_et3k_3d4_23; // note that 22 is missing
	byte store_et3k_3d4_24;
	byte store_et3k_3d4_25;

	//ET3K/ET4K registers
	byte store_3c0_16;
	byte store_3c0_17;

	byte store_3c4_06;
	byte store_3c4_07;

	byte herculescompatibilitymode;
	byte herculescompatibilitymode_secondpage; //Second page of hercules compatibility mode enabled?

	byte extensionstep; //The steps to activate the extensions!
	//Extra data added by superfury(Device specific precalculation storage)

	//Banking support
	byte segmentselectregister; //Containing the below values.
	byte bank_read; //Read bank number!
	byte bank_write; //Write bank number!
	byte bank_size; //The bank size to use(2 bits)!

	//Extended bits
	uint_32 display_start_high;
	uint_32 cursor_start_high;
	uint_32 line_compare_high;
	byte doublehorizontaltimings; //Doubling the horizontal timings!

	//Memory wrapping
	uint_32 memwrap; //The memory wrap to be AND-ed into the address given!

	//Attribute protection?
	byte protect3C0_Overscan; //Disable writes to bits 0-3 of the Overscan?
	byte protect3C0_PaletteRAM; //Disable writes to Internal/External Palette RAM?

	//High color DAC information
	byte hicolorDACcmdmode;
	byte hicolorDACcommand;

	byte CGAModeRegister;
	byte MDAModeRegister;
	byte CGAColorSelectRegister;
	byte ExtendedFeatureControlRegister; //Feature control extension(extra bits)!
	byte useInterlacing; //Interlacing enabled?
} SVGA_ET34K_DATA; //Dosbox ET4000 saved data!

//Retrieve a point to the et4k?
#define et34k(VGA) ((SVGA_ET34K_DATA *)VGA->SVGAExtension)
//Retrieve the active et4k!
#define et34k_data et34k(getActiveVGA())

#define et4k_reg(data,port,index) data->store_et4k_##port##_##index
#define et3k_reg(data,port,index) data->store_et3k_##port##_##index
#define et34k_reg(data,port,index) data->store_##port##_##index

//ET4K register access
#define STORE_ET4K(port, index, category) \
	case 0x##index: \
	if ((getActiveVGA()->enable_SVGA!=1) || ((getActiveVGA()->enable_SVGA==1) && (!et34kdata->extensionsEnabled))) return 0; \
	et34k_data->store_et4k_##port##_##index = val; \
	VGA_calcprecalcs(getActiveVGA(),category|0x##index); \
	return 1;

#define STORE_ET4K_UNPROTECTED(port, index, category) \
	case 0x##index: \
	if (getActiveVGA()->enable_SVGA!=1) return 0; \
	et34k_data->store_et4k_##port##_##index = val; \
	VGA_calcprecalcs(getActiveVGA(),category|0x##index); \
	return 1;

#define RESTORE_ET4K(port, index) \
	case 0x##index: \
		if ((getActiveVGA()->enable_SVGA!=1) || ((getActiveVGA()->enable_SVGA==1) && (!et34kdata->extensionsEnabled))) return 0; \
		*result = et34k_data->store_et4k_##port##_##index; \
		return 1;

#define RESTORE_ET4K_UNPROTECTED(port, index) \
	case 0x##index: \
		if (getActiveVGA()->enable_SVGA!=1) return 0; \
		*result = et34k_data->store_et4k_##port##_##index; \
		return 1;

//ET3K register access
#define STORE_ET3K(port, index, category) \
	case 0x##index: \
		if (getActiveVGA()->enable_SVGA!=2) return 0; \
		et34k_data->store_et3k_##port##_##index = val; \
		VGA_calcprecalcs(getActiveVGA(),category|0x##index); \
		return 1;

#define STORE_ET3K_UNPROTECTED(port, index, category) \
	case 0x##index: \
		if (getActiveVGA()->enable_SVGA!=2) return 0; \
		et34k_data->store_et3k_##port##_##index = val; \
		VGA_calcprecalcs(getActiveVGA(),category|0x##index); \
		return 1;

#define RESTORE_ET3K(port, index) \
	case 0x##index: \
		if (getActiveVGA()->enable_SVGA!=2) return 0; \
		*result = et34k_data->store_et3k_##port##_##index; \
		return 1;

#define RESTORE_ET3K_UNPROTECTED(port, index) \
	case 0x##index: \
		if (getActiveVGA()->enable_SVGA!=2) return 0; \
		*result = et34k_data->store_et3k_##port##_##index; \
		return 1;

//ET3K/ET4K register access
#define STORE_ET34K(port, index, category) \
	case 0x##index: \
	if ((getActiveVGA()->enable_SVGA<1) || (getActiveVGA()->enable_SVGA>2) || ((getActiveVGA()->enable_SVGA==1) && (!et34kdata->extensionsEnabled))) return 0; \
		et34k_data->store_##port##_##index = val; \
		VGA_calcprecalcs(getActiveVGA(),category|0x##index); \
		return 1;

#define STORE_ET34K_UNPROTECTED(port, index, category) \
	case 0x##index: \
	if ((getActiveVGA()->enable_SVGA<1) || (getActiveVGA()->enable_SVGA>2)) return 0; \
		et34k_data->store_##port##_##index = val; \
		VGA_calcprecalcs(getActiveVGA(),category|0x##index); \
		return 1;

#define RESTORE_ET34K(port, index) \
	case 0x##index: \
	if ((getActiveVGA()->enable_SVGA<1) || (getActiveVGA()->enable_SVGA>2) || ((getActiveVGA()->enable_SVGA==1) && (!et34kdata->extensionsEnabled))) return 0; \
		*result = et34k_data->store_##port##_##index; \
		return 1;

#define RESTORE_ET34K_UNPROTECTED(port, index) \
	case 0x##index: \
	if ((getActiveVGA()->enable_SVGA<1) || (getActiveVGA()->enable_SVGA>2)) return 0; \
		*result = et34k_data->store_##port##_##index; \
		return 1;

void SVGA_Setup_TsengET4K(uint_32 VRAMSize);
void set_clock_index_et4k(VGA_Type *VGA, byte index); //Used by the interrupt 10h handler to set the clock index directly!
void set_clock_index_et3k(VGA_Type *VGA, byte index); //Used by the interrupt 10h handler to set the clock index directly!

#endif