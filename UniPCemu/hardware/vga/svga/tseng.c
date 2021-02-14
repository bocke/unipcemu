/*

Copyright (C) 2019 - 2020  Superfury

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

#include "headers/types.h" //Basic types!
#include "headers/hardware/vga/vga.h" //Basic VGA!
#include "headers/hardware/vga/svga/tseng.h" //Our own typedefs!
#include "headers/support/zalloc.h" //Memory allocation for our override support!
#include "headers/hardware/vga/vga_precalcs.h" //Precalculation typedefs etc.
#include "headers/hardware/vga/vga_attributecontroller.h" //Attribute controller support!
#include "headers/hardware/vga/vga_sequencer_graphicsmode.h" //Graphics mode support!
#include "headers/hardware/vga/vga_dacrenderer.h" //DAC rendering support!
#include "headers/hardware/vga/vga_vram.h" //Mapping support for different addressing modes!
#include "headers/cpu/cpu.h" //NMI support!
#include "headers/hardware/vga/vga_vramtext.h" //Extended text mode support!

//Log unhandled (S)VGA accesses on the ET34k emulation?
//#define LOG_UNHANDLED_SVGA_ACCESSES

#ifdef LOG_UNHANDLED_SVGA_ACCESSES
#include "headers/support/log.h" //Logging support!
#endif

// From the depths of X86Config, probably inexact
DOUBLE ET4K_clockFreq[16] = {
	50000000.0, //25MHz: VGA standard clock: 50MHz instead?
	66000000.0, //28MHz: VGA standard clock: 66MHz instead?
	32400000.0, //ET3/4000 clock!
	35900000.0, //ET3/4000 clock!
	39900000.0, //ET3/4000 clock!
	44700000.0, //ET3/4000 clock!
	31400000.0, //ET3/4000 clock!
	37500000.0, //ET3/4000 clock!
	50000000.0, //ET4000 clock!
	56500000.0, //ET4000 clock!
	64900000.0, //ET4000 clock!
	71900000.0, //ET4000 clock!
	79900000.0, //ET4000 clock!
	89600000.0, //ET4000 clock!
	62800000.0, //ET4000 clock!
	74800000.0 //ET4000 clock!
};

DOUBLE ET3K_clockFreq[16] = {
	50000000.0, //25MHz: VGA standard clock: 50MHz instead?
	66000000.0, //28MHz: VGA standard clock: 66MHz instead?
	32400000.0, //ET3/4000 clock!
	35900000.0, //ET3/4000 clock!
	39900000.0, //ET3/4000 clock!
	44700000.0, //ET3/4000 clock!
	31400000.0, //ET3/4000 clock!
	37500000.0, //ET3/4000 clock!
	0.0, //ET3000 clock!
	0.0, //ET3000 clock!
	0.0, //ET3000 clock!
	0.0, //ET3000 clock!
	0.0, //ET3000 clock!
	0.0, //ET3000 clock!
	0.0, //ET3000 clock!
	0.0 //ET3000 clock!
};

OPTINLINE uint_32 getcol256_Tseng(VGA_Type* VGA, byte color) //Convert color to RGB!
{
	byte DACbits;
	DACEntry colorEntry; //For getcol256!
	DACbits = (0x3F | VGA->precalcs.emulatedDACextrabits); //How many DAC bits to use?
	readDAC(VGA, (color & VGA->registers->DACMaskRegister), &colorEntry); //Read the DAC entry, masked on/off by the DAC Mask Register!
	return RGB(convertrel((colorEntry.r & DACbits), DACbits, 0xFF), convertrel((colorEntry.g & DACbits), DACbits, 0xFF), convertrel((colorEntry.b & DACbits), DACbits, 0xFF)); //Convert using DAC (Scale of DAC is RGB64, we use RGB256)!
}

extern uint_32 VGA_MemoryMapBankRead, VGA_MemoryMapBankWrite; //The memory map bank to use!

void updateET34Ksegmentselectregister(byte val)
{
	SVGA_ET34K_DATA* et34kdata = et34k_data; //The et4k data!
	if (getActiveVGA()->enable_SVGA == 2) //ET3000?
	{
		et34kdata->bank_write = val & 7;
		et34kdata->bank_read = (val >> 3) & 7;
		et34kdata->bank_size = (val >> 6) & 3; //Bank size to use!
	}
	else //ET4000?
	{
		et34kdata->bank_write = val & 0xF;
		et34kdata->bank_read = (val >> 4) & 0xF;
		et34kdata->bank_size = 1; //Bank size to use is always the same(64K)!
	}
}

void et34k_updateDAC(SVGA_ET34K_DATA* et34kdata, byte val)
{
	if (et34kdata->emulatedDAC==1) //UMC UM70C178?
	{
		val &= 0xE0; //Mask limited!
	}
	et34kdata->hicolorDACcommand = val; //Apply the command!
	//bits 3-4 redirect to the DAC mask register.
	//bit 0 is set if bits 5-7 is 1 or 3, cleared otherwise(R/O)
	//bits 1-2 are stored, but unused.
	//All generic handling of the ET3K/ET4K Hi-color DAC!
	if (et34kdata->emulatedDAC == 0) //SC11487?
	{
		//It appears that bit 0 is a flag that sets when 16-bit mode isn't selected and 2 pixel clocks per pel are selected, which is an invalid setting.
		et34kdata->hicolorDACcommand = (et34kdata->hicolorDACcommand&~1)|((((val>>2)^val)&(val&0x20))>>5); //Top 3 bits has bit 7 not set while bit 5 set, moved to bit 0?
		//All other bits are fully writable!
		//... They are read-only(proven by the WhatVGA not supposed to be able to bleed bit 4 to the DAC mask register at least!
	}
	else if (et34kdata->emulatedDAC == 2) //AT&T 20C490?
	{
		if ((val&0xE0)==0x60) //Detection logic?
		{
			et34kdata->hicolorDACcommand &= ~0xE0; //Clears the mode bits to VGA mode!
		}
		//All other settings are valid!
	}
	//SC15025 has all bits writable/readable!
	//et34kdata->hicolorDACcommand |= 6; //Always set bits 1-2?
}

byte Tseng34K_writeIO(word port, byte val)
{
	byte result;
	SVGA_ET34K_DATA *et34kdata = et34k_data; //The et4k data!
// Tseng ET4K implementation
	switch (port) //What port?
	{
	case 0x46E8: //Video subsystem enable register?
		if ((et4k_reg(et34kdata, 3d4, 34) & 8) == 0 && (getActiveVGA()->enable_SVGA == 1)) return 0; //Undefined on ET4000!
		SETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,1,1,(val & 8) ? 1 : 0); //RAM enabled?
		return 1; //OK
		break;
	case 0x3C3: //Video subsystem enable register in VGA mode?
		if ((et4k_reg(et34kdata, 3d4, 34) & 8) && (getActiveVGA()->enable_SVGA == 1)) return 2; //Undefined on ET4000!
		SETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,1,1,(val & 1)); //RAM enabled?
		return 1; //OK
		break;
	case 0x3BF: //Hercules Compatibility Mode?
		if (getActiveVGA()->enable_SVGA==1) //Extensions check?
		{
			if (val == 3) //First part of the sequence to activate the extensions?
			{
				et34kdata->extensionstep = 1; //Enable the first step to activation!
			}
			else if (val == 1) //Step one of the disable?
			{
				et34kdata->extensionstep = 2; //Enable the first step to deactivation!
			}
			else
			{
				et34kdata->extensionstep = 0; //Restart the check!
			}
		}
		et34kdata->herculescompatibilitymode = val; //Save the value!
		et34kdata->herculescompatibilitymode_secondpage = ((val & 2) >> 1); //Save the bit!
		return 1; //OK!
		break;
	case 0x3D8: //CGA mode control?
		if (!GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,0,1)) goto finishoutput; //Block: we're a mono mode addressing as color!
		result = 0; //Default result!
		if (((et4k_reg(et34kdata,3d4,34) & 0xA0) == 0x80) || (getActiveVGA()->enable_SVGA==2)) //Enable emulation and translation disabled?
		{
			et34kdata->CGAModeRegister = val; //Save the register to be read!
			if (et34kdata->ExtendedFeatureControlRegister & 0x80) //Enable NMI?
			{
				return !execNMI(0); //Execute an NMI from Bus!
			}
			result = 1; //Handled!
		}
		goto checkEnableDisable;
	case 0x3B8: //MDA mode control?
		if (GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,0,1)) goto finishoutput; //Block: we're a color mode addressing as mono!
		result = 0; //Default result!
		if (((et4k_reg(et34kdata, 3d4, 34) & 0xA0) == 0x80) || (getActiveVGA()->enable_SVGA==2)) //Enable emulation and translation disabled?
		{
			et34kdata->MDAModeRegister = val; //Save the register to be read!
			if (et34kdata->ExtendedFeatureControlRegister & 0x80) //Enable NMI?
			{
				return !execNMI(0); //Execute an NMI from Bus!
			}
			result = 1; //Handled!
		}
		checkEnableDisable: //Check enable/disable(port 3D8 too)
		if (getActiveVGA()->enable_SVGA==1) //Extensions used?
		{
			if ((et34kdata->extensionstep==2) && (val == 0x29)) //Step two of disable extensions?
			{
				et34kdata->extensionstep = 0; //Disable steps!
				et34kdata->extensionsEnabled = 0; //Extensions are now disabled!
				VGA_calcprecalcs(getActiveVGA(), WHEREUPDATED_ALL); //Update all precalcs!
			}
			else if ((et34kdata->extensionstep==1) && (val==0xA0)) //Step two of enable extensions?
			{
				et34kdata->extensionstep = 0; //Disable steps!
				et34kdata->extensionsEnabled = 1; //Enable the extensions!
				et34kdata->et4k_segmentselectregisterenabled = 1; //Enable the segment select register from now on!
				updateET34Ksegmentselectregister(et34kdata->segmentselectregister); //Make the segment select register active!
				VGA_calcprecalcs(getActiveVGA(), WHEREUPDATED_ALL); //Update all precalcs!
			}
			else //Not an extensions trigger?
			{
				et34kdata->extensionstep = 0; //Stop checking!
			}
		}
		return result; //Not handled!
	case 0x3D9: //CGA color control?
		if (((et4k_reg(et34kdata,3d4,34) & 0xA0) == 0x80) || (getActiveVGA()->enable_SVGA==2)) //Enable emulation and translation disabled?
		{
			et34kdata->CGAColorSelectRegister = val; //Save the register to be read!
			/*if (et34kdata->ExtendedFeatureControl & 0x80) //Enable NMI?
			{
				//Execute an NMI!
			}*/ //Doesn't have an NMI?
			return 1; //Handled!
		}
		return 0; //Not handled!
		break;

	//16-bit DAC support(Sierra SC11487)!
	case 0x3C6: //DAC Mask Register? Pixel Mask/Command Register in the manual.
		if (et34kdata->hicolorDACcmdmode<=3)
		{
			et34kdata->hicolorDACcmdmode = 0; //Stop looking?
			return 0; //Execute normally!
		}
		//16-bit DAC operations!
		et34k_updateDAC(et34kdata,val); //Update the DAC values to be compatible!
		if ((et34kdata->emulatedDAC == 2) || (et34kdata->emulatedDAC == 3)) //AT&T 20C490 or Sierra SC15025? This reset of the IPF flag on the SC15025 happens on any write to any address or a read not from the DAC mask address.
		{
			//WhatVGA says this about the UMC70C178 as well, but the identification routine of the AT&T 20C490 would identify it as a AT&T 20C491/20C492 instead, so it should actually be like a Sierra SC11487 instead.
			et34kdata->hicolorDACcmdmode = 0; //Disable command mode!
		}
		VGA_calcprecalcs(getActiveVGA(),WHEREUPDATED_DACMASKREGISTER); //We've been updated!
		//et34kdata->hicolorDACcmdmode = 0; //A write to any address will reset the flag that is set when the pixel read mask register is read four times.
		return 1; //We're overridden!
		break;
	case 0x3C7: //Write: DAC Address Read Mode Register	ADDRESS? Pallette RAM read address register in the manual.
		if (et34kdata->SC15025_enableExtendedRegisters) //Extended registers?
		{
			//Extended index register!
			et34kdata->SC15025_extendedaddress = val; //The selected address!
			return 1; //We're overridden!
		}
		et34kdata->hicolorDACcmdmode = 0; //Disable command mode!
		return 0; //Normal execution!
		break;
	case 0x3C8: //DAC Address Write Mode Register		ADDRESS? Pallette RAM write address register in the manual.
		if (et34kdata->SC15025_enableExtendedRegisters) //Extended registers?
		{
			switch (et34kdata->SC15025_extendedaddress) //Extended data register?
			{
			case 0x08: //Auxiliary Control Register?
				et34kdata->SC15025_auxiliarycontrolregister = val; //Auxiliary control register. Bit 0=8-bit DAC when set. 6-bit otherwise.
				VGA_calcprecalcs(getActiveVGA(), WHEREUPDATED_DACMASKREGISTER); //We've been updated!
				break;
			case 0x09: //ID #1!
			case 0x0A: //ID #2!
			case 0x0B: //ID #3!
			case 0x0C: //Version!
				//ID registers are ROM!
				break;
			case 0x0D: //Secondary pixel mask, low byte!
			case 0x0E: //Secondary pixel mask, mid byte!
			case 0x0F: //Secondary pixel mask, high byte!
				et34kdata->SC15025_secondarypixelmaskregisters[et34kdata->SC15025_extendedaddress-0x0D] = val; //Secondary pixel mask registers!
				VGA_calcprecalcs(getActiveVGA(), WHEREUPDATED_DACMASKREGISTER); //We've been updated!
				break;
			case 0x10: //Pixel repack register!
				et34kdata->SC15025_pixelrepackregister = val; //bit 0=Enable 4-byte fetching in modes 2 and 3!
				VGA_calcprecalcs(getActiveVGA(), WHEREUPDATED_DACMASKREGISTER); //We've been updated!
				break;
			default:
				//Undefined!
				break;
			}
			return 1; //We're overridden!
		}
		et34kdata->hicolorDACcmdmode = 0; //Disable command mode!
		return 0; //Normal execution!
		break;
	case 0x3C9: //DAC Data Register				DATA? Pallette RAM in the manual.
		et34kdata->hicolorDACcmdmode = 0; //Disable command mode!
		return 0; //Normal execution!
		break;
	//RS2 is always zero on x86.

	//Normal video card support!
	case 0x3B5: //CRTC Controller Data Register		DATA
		if (GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,0,1)) goto finishoutput; //Block: we're a color mode addressing as mono!
		goto accesscrtvalue;
	case 0x3D5: //CRTC Controller Data Register		DATA
		if (!GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,0,1)) goto finishoutput; //Block: we're a mono mode addressing as color!
		accesscrtvalue:
		if (((!et34kdata->extensionsEnabled) && (getActiveVGA()->enable_SVGA == 1)) &&
			(!((getActiveVGA()->registers->CRTControllerRegisters_Index==0x33) || (getActiveVGA()->registers->CRTControllerRegisters_Index==0x35))) //Unprotected registers?
			) //ET4000 blocks this without the KEY?
		return 0;

		switch(getActiveVGA()->registers->CRTControllerRegisters_Index)
		{
		/*
		3d4h index 31h (R/W):  General Purpose
		bit  0-3  Scratch pad
			 6-7  Clock Select bits 3-4. Bits 0-1 are in 3C2h/3CCh bits 2-3.
		*/
		STORE_ET4K(3d4, 31,WHEREUPDATED_CRTCONTROLLER);

		// 3d4h index 32h - RAS/CAS Configuration (R/W)
		// No effect on emulation. Should not be written by software.
		STORE_ET4K(3d4, 32,WHEREUPDATED_CRTCONTROLLER);

		case 0x33:
			if (getActiveVGA()->enable_SVGA != 1) return 0; //Not implemented on others than ET4000!
			// 3d4 index 33h (R/W): Extended start Address
			// 0-1 Display Start Address bits 16-17
			// 2-3 Cursor start address bits 16-17
			// Used by standard Tseng ID scheme
			et34kdata->store_et4k_3d4_33 = (val&0xF); //According to Windows NT 4, this only stores the low 4 bits!
			et34kdata->display_start_high = ((val & 0x03)<<16);
			et34kdata->cursor_start_high = ((val & 0x0c)<<14);
			VGA_calcprecalcs(getActiveVGA(),WHEREUPDATED_CRTCONTROLLER|0x33); //Update all precalcs!
			break;

		/*
		3d4h index 34h (R/W): 6845 Compatibility Control Register
		bit    0  Enable CS0 (alternate clock timing)
			   1  Clock Select bit 2.  Bits 0-1 in 3C2h bits 2-3, bits 3-4 are in 3d4h
				  index 31h bits 6-7
			   2  Tristate ET4000 bus and color outputs if set
			   3  Video Subsystem Enable Register at 46E8h if set, at 3C3h if clear.
			   4  Enable Translation ROM for reading CRTC and MISCOUT if set
			   5  Enable Translation ROM for writing CRTC and MISCOUT if set
			   6  Enable double scan in AT&T compatibility mode if set
			   7  Enable 6845 compatibility if set
		*/
		// TODO: Bit 6 may have effect on emulation
		STORE_ET4K(3d4, 34,WHEREUPDATED_CRTCONTROLLER);

		case 0x35: 
		/*
		3d4h index 35h (R/W): Overflow High
		bit    0  Vertical Blank Start Bit 10 (3d4h index 15h).
			   1  Vertical Total Bit 10 (3d4h index 6).
			   2  Vertical Display End Bit 10 (3d4h index 12h).
			   3  Vertical Sync Start Bit 10 (3d4h index 10h).
			   4  Line Compare Bit 10 (3d4h index 18h).
			   5  Gen-Lock Enabled if set (External sync)
			   6  (4000) Read/Modify/Write Enabled if set. Currently not implemented.
			   7  Vertical interlace if set. The Vertical timing registers are
				programmed as if the mode was non-interlaced!!
		*/
			if (getActiveVGA()->enable_SVGA != 1) return 0; //Not implemented on others than ET4000!
			if (GETBITS(getActiveVGA()->registers->CRTControllerRegisters.REGISTERS.VERTICALRETRACEENDREGISTER,7,1)) //Are we protected?
			{
				val = (val&0x90)|(et34k_data->store_et4k_3d4_35&~0x90); //Ignore all bits except bits 4&7(Line compare&vertical interlace)?
			}
			et34kdata->store_et4k_3d4_35 = val;
			et34kdata->line_compare_high = ((val&0x10)<<6);
			VGA_calcprecalcs(getActiveVGA(),WHEREUPDATED_CRTCONTROLLER|0x35); //Update all precalcs!
			break;

		// 3d4h index 36h - Video System Configuration 1 (R/W)
		// VGADOC provides a lot of info on this register, Ferraro has significantly less detail.
		// This is unlikely to be used by any games. Bit 4 switches chipset into linear mode -
		// that may be useful in some cases if there is any software actually using it.
		// TODO (not near future): support linear addressing
		STORE_ET4K(3d4, 36,WHEREUPDATED_CRTCONTROLLER);

		// 3d4h index 37 - Video System Configuration 2 (R/W)
		// Bits 0,1, and 3 provides information about memory size:
		// 0-1 Bus width (1: 8 bit, 2: 16 bit, 3: 32 bit)
		// 3   Size of RAM chips (0: 64Kx, 1: 256Kx)
		// Other bits have no effect on emulation.
		case 0x37:
			if (getActiveVGA()->enable_SVGA != 1) return 0; //Not implemented on others than ET4000!
			if (val != et34kdata->store_et4k_3d4_37) {
				et34kdata->store_et4k_3d4_37 = val;
				et34kdata->memwrap = (((64*1024)<<((val&8)>>2))<<((val&3)-1))-1; //The mask to use for memory!
				VGA_calcprecalcs(getActiveVGA(),WHEREUPDATED_CRTCONTROLLER|0x37); //Update all precalcs!
			}
			return 1;
			break;

		case 0x3f:
		/*
		3d4h index 3Fh (R/W):
		bit    0  Bit 8 of the Horizontal Total (3d4h index 0)
			   2  Bit 8 of the Horizontal Blank Start (3d4h index 3)
			   4  Bit 8 of the Horizontal Retrace Start (3d4h index 4)
			   7  Bit 8 of the CRTC offset register (3d4h index 13h).
		*/
		// The only unimplemented one is bit 7
			if (getActiveVGA()->enable_SVGA != 1) return 0; //Not implemented on others than ET4000!
			et34kdata->store_et4k_3d4_3f = val;
		// Abusing s3 ex_hor_overflow field which very similar. This is
		// to be cleaned up later
			VGA_calcprecalcs(getActiveVGA(),WHEREUPDATED_CRTCONTROLLER|0x3F); //Update all precalcs!
			return 1;
			break;

		//ET3K registers
		STORE_ET3K(3d4, 1b,WHEREUPDATED_CRTCONTROLLER);
		STORE_ET3K(3d4, 1c, WHEREUPDATED_CRTCONTROLLER);
		STORE_ET3K(3d4, 1d, WHEREUPDATED_CRTCONTROLLER);
		STORE_ET3K(3d4, 1e, WHEREUPDATED_CRTCONTROLLER);
		STORE_ET3K(3d4, 1f, WHEREUPDATED_CRTCONTROLLER);
		STORE_ET3K(3d4, 20, WHEREUPDATED_CRTCONTROLLER);
		STORE_ET3K(3d4, 21, WHEREUPDATED_CRTCONTROLLER);
		case 0x23:
			/*
			3d4h index 23h (R/W): Extended start ET3000
			bit   0  Cursor start address bit 16
			1  Display start address bit 16
			2  Zoom start address bit 16
			7  If set memory address 8 is output on the MBSL pin (allowing access to
			1MB), if clear the blanking signal is output.
			*/
			// Only bits 1 and 2 are supported. Bit 2 is related to hardware zoom, bit 7 is too obscure to be useful
			if (getActiveVGA()->enable_SVGA != 2) return 0; //Not implemented on others than ET3000!
			et34k_data->store_et3k_3d4_23 = val;
			et34k_data->display_start_high = ((val & 0x02) << 15);
			et34k_data->cursor_start_high = ((val & 0x01) << 16);
			VGA_calcprecalcs(getActiveVGA(), WHEREUPDATED_CRTCONTROLLER | 0x23); //Update all precalcs!
			break;

			/*
			3d4h index 24h (R/W): Compatibility Control
			bit   0  Enable Clock Translate if set
			1  Clock Select bit 2. Bits 0-1 are in 3C2h/3CCh.
			2  Enable tri-state for all output pins if set
			3  Enable input A8 of 1MB DRAMs from the INTL output if set
			4  Reserved
			5  Enable external ROM CRTC translation if set
			6  Enable Double Scan and Underline Attribute if set
			7  Enable 6845 compatibility if set.
			*/
			// TODO: Some of these may be worth implementing.
		STORE_ET3K(3d4, 24,WHEREUPDATED_CRTCONTROLLER);
		case 0x25:
			/*
			3d4h index 25h (R/W): Overflow High
			bit   0  Vertical Blank Start bit 10
			1  Vertical Total Start bit 10
			2  Vertical Display End bit 10
			3  Vertical Sync Start bit 10
			4  Line Compare bit 10
			5-6  Reserved
			7  Vertical Interlace if set
			*/
			if (getActiveVGA()->enable_SVGA != 2) return 0; //Not implemented on others than ET3000!
			if (GETBITS(getActiveVGA()->registers->CRTControllerRegisters.REGISTERS.VERTICALRETRACEENDREGISTER,7,1)) //Are we protected?
			{
				val = (val&0x90)|(et34k_data->store_et3k_3d4_25&~0x90); //Ignore all bits except bits 4&7(Line compare&vertical interlace)?
			}
			et34k_data->store_et3k_3d4_25 = val;
			VGA_calcprecalcs(getActiveVGA(), WHEREUPDATED_CRTCONTROLLER | 0x25); //Update all precalcs!
			break;
		default:
			//LOG(LOG_VGAMISC,LOG_NORMAL)("VGA:CRTC:ET4K:Write to illegal index %2X", reg);
			break;
		}
		break;
	case 0x3C5: //Sequencer data register?
	//void write_p3c5_et4k(Bitu reg,Bitu val,Bitu iolen) {
		switch(getActiveVGA()->registers->SequencerRegisters_Index) {
		//ET4K
		/*
		3C4h index  6  (R/W): TS State Control
		bit 1-2  Font Width Select in dots/character
				If 3C4h index 4 bit 0 clear:
					0: 9 dots, 1: 10 dots, 2: 12 dots, 3: 6 dots
				If 3C4h index 5 bit 0 set:
					0: 8 dots, 1: 11 dots, 2: 7 dots, 3: 16 dots
				Only valid if 3d4h index 34h bit 3 set.
		*/
		// TODO: Figure out if this has any practical use
		STORE_ET34K(3c4, 06,WHEREUPDATED_SEQUENCER);
		// 3C4h index  7  (R/W): TS Auxiliary Mode
		// Unlikely to be used by games (things like ROM enable/disable and emulation of VGA vs EGA)
		STORE_ET34K(3c4, 07,WHEREUPDATED_SEQUENCER);
		case 0: //TS register special stuff?
			break; //Don't handle the Segment Select disabling!
			if ((val & 2) == 0) //We're stopping to repond to the Segment Select Register when a synchronous reset is started or set!
			{
				et34kdata->et4k_segmentselectregisterenabled = 0; //We're stopping to respond to the Segment Select Register until the KEY is set again!
				updateET34Ksegmentselectregister(0); //Make the segment select register inactive!
				VGA_calcprecalcs(getActiveVGA(), WHEREUPDATED_CRTCONTROLLER | 0x36); //Update from the CRTC controller registers!
			}
		default:
			//LOG(LOG_VGAMISC,LOG_NORMAL)("VGA:SEQ:ET4K:Write to illegal index %2X", reg);
			break;
		}
		break;
	/*
	3CDh (R/W): Segment Select
	bit 0-3  64k Write bank number (0..15)
	4-7  64k Read bank number (0..15)
	*/
	//void write_p3cd_et4k(Bitu port, Bitu val, Bitu iolen) {
	case 0x3CD: //Segment select?
		if ((getActiveVGA()->enable_SVGA == 1) && (!et34kdata->et4k_segmentselectregisterenabled)) return 0; //Not available on the ET4000 until having set the KEY at least once after a power-on reset or synchronous reset(TS indexed register 0h bit 1).
		et34kdata->segmentselectregister = val; //Save the entire segment select register!

		//Apply correct memory banks!
		updateET34Ksegmentselectregister(et34kdata->segmentselectregister); //Make the segment select register active!
		VGA_calcprecalcs(getActiveVGA(),WHEREUPDATED_CRTCONTROLLER|0x36); //Update from the CRTC controller registers!
		return 1;
		break;
	case 0x3C0: //Attribute controller?
		//void write_p3c0_et4k(Bitu reg, Bitu val, Bitu iolen) {
		if (!VGA_3C0_FLIPFLOPR) return 0; //Index gets ignored!
		if (et34kdata->protect3C0_PaletteRAM && (VGA_3C0_INDEXR<0x10)) //Palette RAM? Handle protection!
		{
			VGA_3C0_FLIPFLOPW(!VGA_3C0_FLIPFLOPR); //Flipflop!
			return 1; //Ignore the write: we're protected!
		}
		switch (VGA_3C0_INDEXR) {
			// 3c0 index 16h: ATC Miscellaneous
			// VGADOC provides a lot of information, Ferarro documents only two bits
			// and even those incompletely. The register is used as part of identification
			// scheme.
			// Unlikely to be used by any games but double timing may be useful.
			// TODO: Figure out if this has any practical use
			STORE_ET34K_3C0(3c0, 16,WHEREUPDATED_ATTRIBUTECONTROLLER);
			/*
			3C0h index 17h (R/W):  Miscellaneous 1
			bit   7  If set protects the internal palette ram and redefines the attribute
			bits as follows:
			Monochrome:
			bit 0-2  Select font 0-7
			3  If set selects blinking
			4  If set selects underline
			5  If set prevents the character from being displayed
			6  If set displays the character at half intensity
			7  If set selects reverse video
			Color:
			bit 0-1  Selects font 0-3
			2  Foreground Blue
			3  Foreground Green
			4  Foreground Red
			5  Background Blue
			6  Background Green
			7  Background Red
			*/
			// TODO: Figure out if this has any practical use
			STORE_ET34K_3C0(3c0, 17,WHEREUPDATED_ATTRIBUTECONTROLLER);
		case 0x11: //Overscan? Handle protection!
			if (et34kdata->protect3C0_Overscan) //Palette RAM? Handle protection!
			{
				//Overscan low 4 bits are protected, handle this way!
				val = (val&0xF0)|(getActiveVGA()->registers->AttributeControllerRegisters.DATA[0x11]&0xF); //Leave the low 4 bits unmodified!
				getActiveVGA()->registers->AttributeControllerRegisters.DATA[0x11] = val; //Set the bits allowed to be set!
				VGA_calcprecalcs(getActiveVGA(),WHEREUPDATED_ATTRIBUTECONTROLLER|0x11); //We have been updated!
				VGA_calcprecalcs(getActiveVGA(),WHEREUPDATED_CRTCONTROLLER|VGA_CRTC_ATTRIBUTECONTROLLERTOGGLEREGISTER); //Our actual location!
				VGA_3C0_FLIPFLOPW(!VGA_3C0_FLIPFLOPR); //Flipflop!
				return 1; //We're overridden!
			}
			return 0; //Handle normally!
			break;
		default:
			//LOG(LOG_VGAMISC, LOG_NORMAL)("VGA:ATTR:ET4K:Write to illegal index %2X", reg);
			break;
		}
		break;
	case 0x3BA: //Write: Feature Control Register (mono)		DATA
		if (GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,0,1)) goto finishoutput; //Block: we're a color mode addressing as mono!
		goto accessfc;
	case 0x3CA: //Same as above!
	case 0x3DA: //Same!
		if (!GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,0,1)) goto finishoutput; //Block: we're a mono mode addressing as color!
	accessfc: //Allow!
		getActiveVGA()->registers->ExternalRegisters.FEATURECONTROLREGISTER = val; //Set!
		if (et34kdata->extensionsEnabled || (getActiveVGA()->enable_SVGA!=1)) //Enabled extensions?
		{
			et34kdata->ExtendedFeatureControlRegister = (val&0x80); //Our extended bit is saved!
		}
		VGA_calcprecalcs(getActiveVGA(), WHEREUPDATED_FEATURECONTROLREGISTER); //We have been updated!
		return 1;
		break;
	default: //Unknown port?
		return 0;
		break;
	}
	finishoutput:
	return 0; //Unsupported port!
}

byte Tseng34K_readIO(word port, byte *result)
{
	byte switchval;
	SVGA_ET34K_DATA *et34kdata = et34k_data; //The et4k data!
	switch (port)
	{
	case 0x46E8: //Video subsystem enable register?
		if ((et4k_reg(et34kdata,3d4,34)&8)==0) return 0; //Undefined!
		*result = (GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,1,1)<<3); //RAM enabled?
		return 1; //OK!
		break;
	case 0x3C3: //Video subsystem enable register in VGA mode?
		if (et4k_reg(et34kdata,3d4,34)&8) return 2; //Undefined!
		*result = GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,1,1); //RAM enabled?
		return 1; //OK!
		break;
	case 0x3BF: //Hercules Compatibility Mode?
		*result = et34kdata->herculescompatibilitymode; //The entire saved register!
		if ((!et34kdata->extensionsEnabled) && (getActiveVGA()->enable_SVGA==1)) //Extensions disabled?
		{
			return 0;
		}
		return 1; //OK!
		break;
	case 0x3B8: //MDA mode control?
		if (GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,0,1)) goto finishinput; //Block: we're a color mode addressing as mono!
		if (((et4k_reg(et34kdata, 3d4, 34) & 0xA0) == 0x80) || (getActiveVGA()->enable_SVGA==2)) //Enable emulation and translation disabled?
		{
			*result = et34kdata->MDAModeRegister; //Save the register to be read!
			SETBITS(*result, 6, 1, GETBITS(et34kdata->herculescompatibilitymode,1,1));
			/*if (et34kdata->ExtendedFeatureControl & 0x80) //Enable NMI?
			{
				//Execute an NMI!
			}*/ //Doesn't do NMIs?
			return 1; //Handled!
		}
		return 0; //Not handled!
	case 0x3D8: //CGA mode control?
		if (!GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,0,1)) goto finishinput; //Block: we're a mono mode addressing as color!
		if ((et4k_reg(et34kdata, 3d4, 34) & 0xA0) == 0x80) //Enable emulation and translation disabled?
		{
			*result = et34kdata->CGAModeRegister; //Save the register to be read!
			SETBITS(*result, 6, 1, GETBITS(et34kdata->herculescompatibilitymode, 1, 1));
			/*if (et34kdata->ExtendedFeatureControl & 0x80) //Enable NMI?
			{
			//Execute an NMI!
			}*/ //Doesn't do NMIs?
			return 1; //Handled!
		}
		return 0; //Not handled!
	case 0x3D9: //CGA color control?
		if ((et4k_reg(et34kdata, 3d4, 34) & 0xA0) == 0x80) //Enable emulation and translation disabled?
		{
			*result = et34kdata->CGAColorSelectRegister; //Save the register to be read!
			/*if (et34kdata->ExtendedFeatureControl & 0x80) //Enable NMI?
			{
			//Execute an NMI!
			}*/ //Doesn't do NMIs?
			return 1; //Handled!
		}
		return 0; //Not handled!
		break;

		//16-bit DAC support(Sierra SC11487)!
	case 0x3C6: //DAC Mask Register?
		if (et34kdata->hicolorDACcmdmode<=3)
		{
			++et34kdata->hicolorDACcmdmode;
			return 0; //Execute normally!
		}
		else
		{
			*result = et34kdata->hicolorDACcommand;
			if (et34kdata->emulatedDAC == 0) //SC11487?
			{
				*result = (*result&~0x18)|(getActiveVGA()->registers->DACMaskRegister&0x18); //Mask in the shared bits only!
			}
			if (et34kdata->emulatedDAC==2) //AT&T 20C490?
			{
				et34kdata->hicolorDACcmdmode = 0; //Return to normal mode!
			}
			return 1; //Handled!
		}
		break;
	case 0x3C7: //Write: DAC Address Read Mode Register	ADDRESS? Pallette RAM read address register in the manual.
		et34kdata->hicolorDACcmdmode = 0; //Disable command mode!
		return 0; //Execute normally!
		break;
	case 0x3C8: //DAC Address Write Mode Register		ADDRESS? Pallette RAM write address register in the manual.
		if (et34kdata->SC15025_enableExtendedRegisters) //Extended registers?
		{
			//Extended data register!
			switch (et34kdata->SC15025_extendedaddress) //Extended data register?
			{
			case 0x08: //Auxiliary Control Register?
				*result = et34kdata->SC15025_auxiliarycontrolregister; //Auxiliary control register. Bit 0=8-bit DAC when set. 6-bit otherwise.
				break;
			case 0x09: //ID #1!
				*result = 0x53; //ID registers are ROM!
				break;
			case 0x0A: //ID #2!
				*result = 0x3A; //ID registers are ROM!
				break;
			case 0x0B: //ID #3!
				*result = 0xB1; //ID registers are ROM!
				break;
			case 0x0C: //Version!
				*result = 0x41; //Version register is ROM!
				break;
			case 0x0D: //Secondary pixel mask, low byte!
			case 0x0E: //Secondary pixel mask, mid byte!
			case 0x0F: //Secondary pixel mask, high byte!
				*result = et34kdata->SC15025_secondarypixelmaskregisters[et34kdata->SC15025_extendedaddress - 0x0D]; //Secondary pixel mask registers!
				break;
			case 0x10: //Pixel repack register!
				*result = et34kdata->SC15025_pixelrepackregister; //bit 0=Enable 4-byte fetching in modes 2 and 3!
				break;
			default: //Unknown register!
				*result = ~0; //Undefined!
				break;
			}
			return 1; //We're overridden!
		}
		et34kdata->hicolorDACcmdmode = 0; //Disable command mode!
		return 0; //Execute normally!
		break;
	case 0x3C9: //DAC Data Register				DATA? Pallette RAM in the manual.
		if (et34kdata->SC15025_enableExtendedRegisters) //Extended registers?
		{
			//Extended index register!
			*result = et34kdata->SC15025_extendedaddress; //Extended index!
			return 1; //We're overridden!
		}
		et34kdata->hicolorDACcmdmode = 0; //Disable command mode!
		return 0; //Execute normally!
		break;
	//Normal video card support!
	case 0x3B5: //CRTC Controller Data Register		5DATA
		if (GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,0,1)) goto finishinput; //Block: we're a color mode addressing as mono!
		goto readcrtvalue;
	case 0x3D5: //CRTC Controller Data Register		DATA
		if (!GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER,0,1)) goto finishinput; //Block: we're a mono mode addressing as color!
		readcrtvalue:
	//Bitu read_p3d5_et4k(Bitu reg,Bitu iolen) {
		if (((!et34kdata->extensionsEnabled) && (getActiveVGA()->enable_SVGA == 1)) &&
			(!((getActiveVGA()->registers->CRTControllerRegisters_Index == 0x33) || (getActiveVGA()->registers->CRTControllerRegisters_Index == 0x35))) //Unprotected registers?
			) //ET4000 blocks this without the KEY?
			return 0;
		switch(getActiveVGA()->registers->CRTControllerRegisters_Index)
		{
		//ET4K
		RESTORE_ET4K(3d4, 31);
		RESTORE_ET4K(3d4, 32);
		RESTORE_ET4K_UNPROTECTED(3d4, 33);
		RESTORE_ET4K(3d4, 34);
		RESTORE_ET4K_UNPROTECTED(3d4, 35);
		RESTORE_ET4K(3d4, 36);
		RESTORE_ET4K(3d4, 37);
		RESTORE_ET4K(3d4, 3f);
		//ET3K
		RESTORE_ET3K(3d4, 1b);
		RESTORE_ET3K(3d4, 1c);
		RESTORE_ET3K(3d4, 1d);
		RESTORE_ET3K(3d4, 1e);
		RESTORE_ET3K(3d4, 1f);
		RESTORE_ET3K(3d4, 20);
		RESTORE_ET3K(3d4, 21);
		RESTORE_ET3K(3d4, 23);
		RESTORE_ET3K(3d4, 24);
		RESTORE_ET3K(3d4, 25);
		default:
			//LOG(LOG_VGAMISC,LOG_NORMAL)("VGA:CRTC:ET4K:Read from illegal index %2X", reg);
			return 0;
			break;
		}
	case 0x3C5: //Sequencer data register?
	//Bitu read_p3c5_et4k(Bitu reg,Bitu iolen) {
		switch(getActiveVGA()->registers->SequencerRegisters_Index) {
		RESTORE_ET34K(3c4, 06);
		RESTORE_ET34K(3c4, 07);
		default:
			//LOG(LOG_VGAMISC,LOG_NORMAL)("VGA:SEQ:ET4K:Read from illegal index %2X", reg);
			break;
		}
		break;
	case 0x3CD: //Segment select?
	//Bitu read_p3cd_et4k(Bitu port, Bitu iolen) {
		if ((getActiveVGA()->enable_SVGA == 1) && (!et34kdata->et4k_segmentselectregisterenabled)) return 0; //Not available on the ET4000 until having set the KEY at least once after a power-on reset or synchronous reset(TS indexed register 0h bit 1).
		*result = et34kdata->segmentselectregister; //Give the saved segment select register!
		return 1; //Supported!
		break;
	case 0x3C1: //Attribute controller read?
	//Bitu read_p3c1_et4k(Bitu reg, Bitu iolen) {
		switch (VGA_3C0_INDEXR) {
			RESTORE_ET34K(3c0, 16);
			RESTORE_ET34K(3c0, 17);
		default:
			//LOG(LOG_VGAMISC, LOG_NORMAL)("VGA:ATTR:ET4K:Read from illegal index %2X", reg);
			break;
		}
		break;
	case 0x3C2: //Read: Input Status #0 Register		DATA
		//Switch sense: 0=Switch closed(value of the switch being 1)
		switchval = ((getActiveVGA()->registers->switches) >> GETBITS(getActiveVGA()->registers->ExternalRegisters.MISCOUTPUTREGISTER, 2, 3)); //Switch value to set!
		switchval = ~switchval; //Reverse the switch for EGA+!
		SETBITS(getActiveVGA()->registers->ExternalRegisters.INPUTSTATUS0REGISTER, 4, 1, (switchval & 1)); //Depends on the switches. This is the reverse of the actual switches used! Originally stuck to 1s, but reported as 0110!
		*result = getActiveVGA()->registers->ExternalRegisters.INPUTSTATUS0REGISTER; //Give the register!
		//*result &= VGA_RegisterWriteMasks_InputStatus0[(getActiveVGA()->enable_SVGA == 3) ? 1 : 0]; //Apply the write mask to the data written to the register!
		if ((!et34kdata->extensionsEnabled) && (getActiveVGA()->enable_SVGA == 1)) //Disabled on ET4000?
		{
			*result &= ~0x60; //Disable reading of the extended register!
		}
		else //Feature code!
		{
			SETBITS(*result, 5, 3, (getActiveVGA()->registers->ExternalRegisters.FEATURECONTROLREGISTER & 3)); //Feature bits 0&1!
		}
		SETBITS(*result, 7, 1, GETBITS(getActiveVGA()->registers->CRTControllerRegisters.REGISTERS.VERTICALRETRACEENDREGISTER, 4, 1)); //Vertical retrace interrupt pending?
		return 1;
		break;
	case 0x3CA: //Read: Feature Control Register		DATA
		*result = getActiveVGA()->registers->ExternalRegisters.FEATURECONTROLREGISTER; //Give!
		if (((et34kdata->extensionsEnabled) && (getActiveVGA()->enable_SVGA==1)) || (getActiveVGA()->enable_SVGA==2)) //Enabled extensions?
		{
			*result &= 0x7F; //Clear our extension bit!
			*result |= et34kdata->ExtendedFeatureControlRegister; //Add the extended feature control!
		}
		return 1;
		break;
	default: //Unknown port?
		break;
	}
	finishinput:
	return 0; //Unsupported port!
}

/*
These ports are used but have little if any effect on emulation:
	3BFh (R/W): Hercules Compatibility Mode
	3CBh (R/W): PEL Address/Data Wd
	3CEh index 0Dh (R/W): Microsequencer Mode
	3CEh index 0Eh (R/W): Microsequencer Reset
	3d8h (R/W): Display Mode Control
	3DEh (W);  AT&T Mode Control Register
*/

OPTINLINE byte get_clock_index_et4k(VGA_Type *VGA) {
	// Ignoring bit 4, using "only" 16 frequencies. Looks like most implementations had only that
	return ((VGA->registers->ExternalRegisters.MISCOUTPUTREGISTER>>2)&3) | ((et34k(VGA)->store_et4k_3d4_34<<1)&4) | ((et34k(VGA)->store_et4k_3d4_31>>3)&8);
}

OPTINLINE byte get_clock_index_et3k(VGA_Type *VGA) {
	// Ignoring bit 4, using "only" 16 frequencies. Looks like most implementations had only that
	return ((VGA->registers->ExternalRegisters.MISCOUTPUTREGISTER >> 2) & 3) | ((et34k(VGA)->store_et4k_3d4_34 << 1) & 4);
}

void set_clock_index_et4k(VGA_Type *VGA, byte index) { //Used by the interrupt 10h handler to set the clock index directly!
	// Shortwiring register reads/writes for simplicity
	et34k_data->store_et4k_3d4_34 = (et34k(VGA)->store_et4k_3d4_34&~0x02)|((index&4)>>1);
	et34k_data->store_et4k_3d4_31 = (et34k(VGA)->store_et4k_3d4_31&~0xc0)|((index&8)<<3); // (index&0x18) if 32 clock frequencies are to be supported
	PORT_write_MISC_3C2((VGA->registers->ExternalRegisters.MISCOUTPUTREGISTER&~0x0c)|((index&3)<<2));
}

void set_clock_index_et3k(VGA_Type *VGA, byte index) {
	// Shortwiring register reads/writes for simplicity
	et34k_data->store_et3k_3d4_24 = (et34k_data->store_et3k_3d4_24&~0x02) | ((index & 4) >> 1);
	PORT_write_MISC_3C2((VGA->registers->ExternalRegisters.MISCOUTPUTREGISTER&~0x0c)|((index&3)<<2));
}

extern byte EMU_VGAROM[0x10000];

uint_32 Tseng4k_VRAMSize = 0; //Setup VRAM size?

extern BIOS_Settings_TYPE BIOS_Settings; //Current BIOS settings to be updated!

void Tseng34k_init()
{
	byte *Tseng_VRAM = NULL; //The new VRAM to use with our card!
	if (getActiveVGA()) //Gotten active VGA? Initialise the full hardware if needed!
	{
		if ((getActiveVGA()->enable_SVGA==1) || (getActiveVGA()->enable_SVGA==2)) //Are we enabled as SVGA?
		{
			//Handle all that needs to be initialized for the Tseng 4K!
			// Default to 1M of VRAM
			if (getActiveVGA()->enable_SVGA==1) //ET4000?
			{
				byte n,isvalid;
				isvalid = 0; //Default: invalid!
				uint_32 maxsize=0,cursize;
				for (n = 0; n < 0x10; ++n) //Try all VRAM sizes!
				{
					cursize = ((64 * 1024) << ((n & 8) >> 2)) << ((n & 3)); //size?
					if (Tseng4k_VRAMSize == cursize) isvalid = 1; //The memory size for this item!
					if ((cursize > maxsize) && (cursize <= Tseng4k_VRAMSize)) maxsize = cursize; //Newer within range!
				}
				if (!isvalid) //Invalid VRAM size?
				{
					Tseng4k_VRAMSize = maxsize?maxsize:1024 * 1024; //Always 1M or next smaller if possible!
					BIOS_Settings.VRAM_size = Tseng4k_VRAMSize; //Update VRAM size in BIOS!
				}
				//1M+=OK!
			}
			else //ET3000?
			{
				Tseng4k_VRAMSize = 512 * 1024; //Always 512K! (Dosbox says: "Cannot figure how this was supposed to work on the real card")
				BIOS_Settings.VRAM_size = Tseng4k_VRAMSize; //Update VRAM size in BIOS!
			}

			debugrow("VGA: Allocating SVGA VRAM...");
			Tseng_VRAM = (byte *)zalloc(Tseng4k_VRAMSize, "VGA_VRAM", getLock(LOCK_CPU)); //The VRAM allocated to 0!
			if (Tseng_VRAM) //VRAM allocated?
			{
				freez((void **)&getActiveVGA()->VRAM,getActiveVGA()->VRAM_size,"VGA_VRAM"); //Release the original VGA VRAM!
				getActiveVGA()->VRAM = Tseng_VRAM; //Assign the new Tseng VRAM instead!
				getActiveVGA()->VRAM_size = Tseng4k_VRAMSize; //Assign the Tseng VRAM size!
			}

			byte VRAMsize = 0;
			byte regval=0; //Highest memory size that fits!
			uint_32 memsize; //Current memory size!
			uint_32 lastmemsize = 0; //Last memory size!
			for (VRAMsize = 0;VRAMsize < 0x10;++VRAMsize) //Try all VRAM sizes!
			{
				memsize = ((64 * 1024) << ((VRAMsize & 8) >> 2)) << ((VRAMsize & 3)); //The memory size for this item!
				if ((memsize > lastmemsize) && (memsize <= Tseng4k_VRAMSize)) //New best match found?
				{
					regval = VRAMsize; //Use this as the new best!
					lastmemsize = memsize; //Use this as the last value found!
				}
			}
			et4k_reg(et34k(getActiveVGA()),3d4,37) = regval; //Apply the best register value describing our memory!
			et34k(getActiveVGA())->memwrap = (lastmemsize-1); //The memory size used!

			// Tseng ROM signature
			EMU_VGAROM[0x0075] = ' ';
			EMU_VGAROM[0x0076] = 'T';
			EMU_VGAROM[0x0077] = 's';
			EMU_VGAROM[0x0078] = 'e';
			EMU_VGAROM[0x0079] = 'n';
			EMU_VGAROM[0x007a] = 'g';
			EMU_VGAROM[0x007b] = ' ';

			et34k(getActiveVGA())->extensionsEnabled = 0; //Disable the extensions by default!
			et34k(getActiveVGA())->oldextensionsEnabled = 1; //Make sure the extensions are updated in status!
			et34k(getActiveVGA())->et4k_segmentselectregisterenabled = 0; //Segment select register isn't enabled yet!
			et34k(getActiveVGA())->emulatedDAC = BIOS_Settings.SVGA_DACmode; //The emulated DAC mode!
			et34k(getActiveVGA())->SC15025_secondarypixelmaskregisters[0] = 0xFF; //Default value!
			et34k(getActiveVGA())->SC15025_secondarypixelmaskregisters[1] = 0xFF; //Default value!
			et34k(getActiveVGA())->SC15025_secondarypixelmaskregisters[2] = 0xFF; //Default value!
			et34k_updateDAC(et34k(getActiveVGA()), et34k(getActiveVGA())->hicolorDACcommand); //Initialize the DAC command register to compatible values!

			VGA_calcprecalcs(getActiveVGA(),WHEREUPDATED_ALL); //Update all precalcs!
		}
	}
}

extern byte VGAROM_mapping; //Default: all mapped in!

byte Tseng34k_doublecharacterclocks(VGA_Type *VGA)
{
	if (!(((VGA->enable_SVGA == 2) || (VGA->enable_SVGA == 1)))) return 0; //Not ET3000/ET4000!
	if (!et34k(VGA)) return 0; //Not registered?
	return et34k(VGA)->doublehorizontaltimings; //Double the horizontal timings?
}

extern byte VGA_WriteMemoryMode, VGA_ReadMemoryMode; //Write/read memory modes used for accessing VRAM!
//ET4K precalcs updating functionality.
void Tseng34k_calcPrecalcs(void *useVGA, uint_32 whereupdated)
{
	VGA_Type *VGA = (VGA_Type *)useVGA; //The VGA to work on!
	SVGA_ET34K_DATA *et34kdata = et34k(VGA); //The et4k data!
	byte updateCRTC = 0; //CRTC updated?
	byte horizontaltimingsupdated = 0; //Horizontal timings are updated?
	byte verticaltimingsupdated = 0; //Vertical timings are updated?
	byte et34k_tempreg;
	byte DACmode; //Current/new DAC mode!
	byte newcharwidth, newtextwidth; //Change detection!
	byte newfontwidth; //Change detection!
	uint_32 tempdata; //Saved data!
	byte tempval;
	if (!et34k(VGA)) return; //No extension registered?

	byte FullUpdate = (whereupdated == 0); //Fully updated?
	byte charwidthupdated = ((whereupdated == (WHEREUPDATED_SEQUENCER | 0x01)) || FullUpdate || VGA->precalcs.charwidthupdated); //Sequencer register updated?
	byte CRTUpdated = UPDATE_SECTIONFULL(whereupdated, WHEREUPDATED_CRTCONTROLLER, FullUpdate); //Fully updated?
	byte CRTUpdatedCharwidth = CRTUpdated || charwidthupdated; //Character width has been updated, for following registers using those?
	byte AttrUpdated = UPDATE_SECTIONFULL(whereupdated,WHEREUPDATED_ATTRIBUTECONTROLLER,FullUpdate); //Fully updated?
	byte SequencerUpdated = UPDATE_SECTIONFULL(whereupdated, WHEREUPDATED_SEQUENCER, FullUpdate); //Fully updated?
	byte linearmodeupdated = 0; //Linear mode has been updated?


	#ifdef LOG_UNHANDLED_SVGA_ACCESSES
	byte handled = 0;
	#endif

	if ((whereupdated==WHEREUPDATED_ALL) || (whereupdated==(WHEREUPDATED_SEQUENCER|0x7))) //TS Auxiliary Mode updated?
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		et34k_reg(et34kdata,3c4,07) |= 0x04; //Always set!
		if (VGA->enable_SVGA==1) //ET4000?
		{
			et34k_reg(et34kdata,3c4,07) |= 0x10; //ET4000 rev E always sets this bit!
		}
		et34k_tempreg = et34k_reg(et34kdata,3c4,07); //The TS Auxiliary mode to apply!
		if (et34k_tempreg&0x1) //MCLK/4?
		{
			VGA->precalcs.MemoryClockDivide = 2; //Divide by 4!
		}
		else if (et34k_tempreg&0x40) //MCLK/2?
		{
			VGA->precalcs.MemoryClockDivide = 1; //Divide by 2!
		}
		else //Normal 1:1 MCLK!
		{
			VGA->precalcs.MemoryClockDivide = 0; //Do not divide!
		}
		/*
		if (et34k_tempreg & 0x80) //VGA-compatible settings instead of EGA-compatible settings?
		{
			goto VGAcompatibleMCLK;
		}*/
		VGAROM_mapping = ((et34k_tempreg&8)>>2)|((et34k_tempreg&0x20)>>5); //Bit 3 is the high bit, Bit 5 is the low bit!
	}

	//Bits 4-5 of the Attribute Controller register 0x16(Miscellaneous) determine the mode to be used when decoding pixels:
	/*
	00=Normal power-up/default(VGA mode)
	01=Reserved
	10=High-resolution mode (up to 256 colors)
	11=High-color 16-bits/pixel
	*/

	if (AttrUpdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_ATTRIBUTECONTROLLER|0x16)) || (whereupdated == (WHEREUPDATED_ATTRIBUTECONTROLLER | 0x10)) || (whereupdated == (WHEREUPDATED_SEQUENCER | 0x7))) //Attribute misc. register?
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		et34k_tempreg = et34k_reg(et34kdata,3c0,16); //The mode to use when decoding!

		VGA->precalcs.BypassPalette = (et34k_tempreg&0x80)?1:0; //Bypass the palette if specified!
		et34kdata->protect3C0_Overscan = (et34k_tempreg&0x01)?1:0; //Protect overscan if specified!
		et34kdata->protect3C0_PaletteRAM = (et34k_tempreg&0x02)?1:0; //Protect Internal/External Palette RAM if specified!
		horizontaltimingsupdated = (et34kdata->doublehorizontaltimings != (((et34k_tempreg&0x10) && (VGA->enable_SVGA==2))?1:0)); //Horizontal timings double has been changed?
		et34kdata->doublehorizontaltimings = (((et34k_tempreg & 0x10) && (VGA->enable_SVGA == 2))?1:0); //Double the horizontal timings?
		VGA->precalcs.charactercode_16bit = ((et34k_tempreg & 0x40) >> 6); //The new character code size!

		et34k_tempreg >>= 4; //Shift to our position!
		et34k_tempreg &= 3; //Only 2 bits are used for detection!
		if (VGA->enable_SVGA==2) et34k_tempreg = 0; //Unused on the ET3000! Force default mode!
		//Manual says: 00b=Normal power-up default, 01b=High-resolution mode(up to 256 colors), 10b=Reserved, 11b=High-color 16-bit/pixel
		if (et34k_tempreg==2) //The third value is illegal(reserved in the manual)!
		{
			et34k_tempreg = 0; //Ignore the reserved value, forcing VGA mode in that case!
		}
		if ((et34k_reg(et34kdata, 3c4, 07) & 2) == 0) //SCLK not divided? Then we're in normal mode!
		{
			et34k_tempreg = 0; //Ignore the reserved value, forcing VGA mode in that case!
		}
		VGA->precalcs.AttributeController_16bitDAC = et34k_tempreg; //Set the new mode to use (mode 2/3 or 0)!
		//Modes 2&3 set forced 8-bit and 16-bit Attribute modes!
		updateVGAAttributeController_Mode(VGA); //Update the attribute controller mode, which might have changed!
		updateVGAGraphics_Mode(VGA);
	}

	if (AttrUpdated || (whereupdated==(WHEREUPDATED_ATTRIBUTECONTROLLER|0x13)) //Updated horizontal panning?
			|| (whereupdated == (WHEREUPDATED_GRAPHICSCONTROLLER | 0x06)) //Updated text mode?
			|| charwidthupdated //Char width updated?
			) //Horizontal pixel panning is to be updated?
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		//Precalculate horizontal pixel panning:
		byte pixelboost = 0; //Actual pixel boost!
		byte possibleboost; //Possible value!
		possibleboost = GETBITS(VGA->registers->AttributeControllerRegisters.REGISTERS.HORIZONTALPIXELPANNINGREGISTER,0,0xF); //Possible value, to be determined!
		if ((GETBITS(VGA->registers->SequencerRegisters.REGISTERS.CLOCKINGMODEREGISTER, 0, 1) == 0) && (VGA->precalcs.graphicsmode)) //Different behaviour with 9 pixel modes?
		{
			if (possibleboost >= 8) //No shift?
			{
				possibleboost = 0; //No shift!
			}
			else //Less than 8?
			{
				++possibleboost; //1 more!
			}
		}
		else //Only 3 bits?
		{
			possibleboost &= 0x7; //Repeat the low values!
		}
		pixelboost = possibleboost; //Enable normally!
		//dolog("VGA","VTotal after pixelboost: %u",VGA->precalcs.verticaltotal); //Log it!
		VGA->precalcs.recalcScanline |= (VGA->precalcs.pixelshiftcount!=pixelboost); //Recalc scanline data when needed!
		VGA->precalcs.pixelshiftcount = pixelboost; //Save our precalculated value!
	}

	//ET3000/ET4000 Start address register
	if (CRTUpdated || horizontaltimingsupdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER|0x33)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x23)) || (whereupdated==(WHEREUPDATED_CRTCONTROLLER|0xC)) || (whereupdated==(WHEREUPDATED_CRTCONTROLLER|0xD))) //Extended start address?
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		VGA->precalcs.startaddress = (((VGA->precalcs.VGAstartaddress+et34k(VGA)->display_start_high))<<et34kdata->doublehorizontaltimings); //Double the horizontal timings if needed!
	}

	//ET3000/ET4000 Cursor Location register
	if (CRTUpdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x33)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x23)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0xE)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0xF))) //Extended cursor location?
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		VGA->precalcs.cursorlocation = (VGA->precalcs.cursorlocation & 0xFFFF) | et34k(VGA)->cursor_start_high;
	}

	//ET3000/ET4000 Vertical Overflow register!
	if (VGA->enable_SVGA == 1) //ET4000?
	{
		et34k_tempreg = et4k_reg(et34kdata,3d4,35); //The overflow register!
	}
	else //ET3000?
	{
		et34k_tempreg = et3k_reg(et34kdata,3d4,25); //The overflow register!
	}

	verticaltimingsupdated = 0; //Default: not updated!
	if (CRTUpdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x35)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x25))) //Interlacing?
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		verticaltimingsupdated |= (et34kdata->useInterlacing != ((et34k_tempreg & 0x80) ? 1 : 0)); //Interlace has changed?
		et34kdata->useInterlacing = VGA->precalcs.enableInterlacing = (VGA->enable_SVGA==2)?((et34k_tempreg & 0x80) ? 1 : 0):0; //Enable/disable interlacing! Apply with ET3000 only!
	}

	if (CRTUpdated || verticaltimingsupdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x35)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x25)) //Extended bits of the overflow register!
		|| (whereupdated==(WHEREUPDATED_CRTCONTROLLER|0x7)) || //Overflow register itself
		//Finally, bits needed by the overflow register itself(of which we are an extension)!
		(whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x12)) //Vertical display end
		) //Extended bits of the overflow register!
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		//bit2=Vertical display end bit 10
		tempdata = GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.OVERFLOWREGISTER,6,1);
		tempdata <<= 1;
		tempdata |= GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.OVERFLOWREGISTER,1,1);
		tempdata <<= 8;
		tempdata |= VGA->registers->CRTControllerRegisters.REGISTERS.VERTICALDISPLAYENDREGISTER;
		tempdata = ((et34k_tempreg & 4) << 9) | (tempdata & 0x3FF); //Add/replace the new/changed bits!
		tempdata <<= et34kdata->useInterlacing; //Interlacing doubles vertical resolution!
		++tempdata; //One later!
		updateCRTC |= (VGA->precalcs.verticaldisplayend!=tempdata); //To be updated?
		VGA->precalcs.verticaldisplayend = tempdata; //Save the new data!
	}

	if (CRTUpdated || verticaltimingsupdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x35)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x25)) //Extended bits of the overflow register!
		|| (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x7)) || //Overflow register itself
		//Finally, bits needed by the overflow register itself(of which we are an extension)!
		(whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x15)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x9)) //Vertical blanking start
		)
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		//bit0=Vertical blank bit 10
		tempdata = GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.MAXIMUMSCANLINEREGISTER,5,1);
		tempdata <<= 1;
		tempdata |= GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.OVERFLOWREGISTER,3,1);
		tempdata <<= 8;
		tempdata |= VGA->registers->CRTControllerRegisters.REGISTERS.STARTVERTICALBLANKINGREGISTER;
		tempdata = ((et34k_tempreg & 1) << 10) | (tempdata & 0x3FF); //Add/replace the new/changed bits!
		tempdata <<= et34kdata->useInterlacing; //Interlacing doubles vertical resolution!
		updateCRTC |= (VGA->precalcs.verticalblankingstart!=tempdata); //To be updated?
		VGA->precalcs.verticalblankingstart = tempdata; //Save the new data!
	}

	if (CRTUpdated || verticaltimingsupdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x35)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x25)) //Extended bits of the overflow register!
		|| (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x7)) || //Overflow register itself
		//Finally, bits needed by the overflow register itself(of which we are an extension)!
		(whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x10)) //Vertical retrace start
		)
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		//bit3=Vertical sync start bit 10
		tempdata = GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.OVERFLOWREGISTER,7,1);
		tempdata <<= 1;
		tempdata |= GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.OVERFLOWREGISTER,2,1);
		tempdata <<= 8;
		tempdata |= VGA->registers->CRTControllerRegisters.REGISTERS.VERTICALRETRACESTARTREGISTER;
		tempdata = ((et34k_tempreg & 8) << 7) | (tempdata & 0x3FF); //Add/replace the new/changed bits!
		tempdata <<= et34kdata->useInterlacing; //Interlacing doubles vertical resolution!
		updateCRTC |= (VGA->precalcs.verticalretracestart!=tempdata); //To be updated?
		VGA->precalcs.verticalretracestart = tempdata; //Save the new data!
	}

	if (CRTUpdated || verticaltimingsupdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x35)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x25)) //Extended bits of the overflow register!
		|| (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x7)) || //Overflow register itself
		//Finally, bits needed by the overflow register itself(of which we are an extension)!
		(whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x6)) //Vertical total
		)
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		//bit1=Vertical total bit 10
		tempdata = GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.OVERFLOWREGISTER,5,1);
		tempdata <<= 1;
		tempdata |= GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.OVERFLOWREGISTER,0,1);
		tempdata <<= 8;
		tempdata |= VGA->registers->CRTControllerRegisters.REGISTERS.VERTICALTOTALREGISTER;
		tempdata = ((et34k_tempreg & 2) << 9) | (tempdata & 0x3FF); //Add/replace the new/changed bits!
		tempdata <<= et34kdata->useInterlacing; //Interlacing doubles vertical resolution!
		++tempdata; //One later!
		updateCRTC |= (VGA->precalcs.verticaltotal!=tempdata); //To be updated?
		VGA->precalcs.verticaltotal = tempdata; //Save the new data!
	}

	if (CRTUpdated || verticaltimingsupdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x35)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x25)) //Extended bits of the overflow register!
		|| (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x7)) || //Overflow register itself
		//Finally, bits needed by the overflow register itself(of which we are an extension)!
		(whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x18)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x9)) //Line compare
		)
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		//bit4=Line compare bit 10
		tempdata = GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.MAXIMUMSCANLINEREGISTER,6,1);
		tempdata <<= 1;
		tempdata |= GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.OVERFLOWREGISTER,4,1);
		tempdata <<= 8;
		tempdata |= VGA->registers->CRTControllerRegisters.REGISTERS.LINECOMPAREREGISTER;
		tempdata = ((et34k_tempreg & 0x10) << 6) | (tempdata & 0x3FF); //Add/replace the new/changed bits!
		tempdata <<= et34kdata->useInterlacing; //Interlacing doubles vertical resolution!
		++tempdata; //One later!
		updateCRTC |= (VGA->precalcs.topwindowstart!=tempdata); //To be updated?
		VGA->precalcs.topwindowstart = tempdata; //Save the new data!
	}

	//ET4000 horizontal overflow timings!
	et34k_tempreg = et4k_reg(et34kdata, 3d4, 3f); //The overflow register!
	if (VGA->enable_SVGA!=1) et34k_tempreg = 0; //Disable the register with ET3000(always zeroed)!

	if (CRTUpdated || horizontaltimingsupdated || CRTUpdatedCharwidth || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x3F)) //Extended bits of the overflow register!
		//Finally, bits needed by the overflow register itself(of which we are an extension)!
		|| (whereupdated == WHEREUPDATED_CRTCONTROLLER) //Horizontal total
		)
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		//bit0=Horizontal total bit 8
		tempdata = VGA->registers->CRTControllerRegisters.REGISTERS.HORIZONTALTOTALREGISTER;
		tempdata |= ((et34k_tempreg & 1) << 8); //To be updated?
		tempdata += 5; //Actually five clocks more!
		tempdata *= VGA->precalcs.characterwidth; //We're character units!
		tempdata <<= et34kdata->doublehorizontaltimings; //Double the horizontal timings if needed!
		updateCRTC |= (VGA->precalcs.horizontaltotal != tempdata); //To be updated?
		VGA->precalcs.horizontaltotal = tempdata; //Save the new data!
	}
	
	if (CRTUpdated || horizontaltimingsupdated || CRTUpdatedCharwidth || (whereupdated==WHEREUPDATED_ALL) || (whereupdated==(WHEREUPDATED_CRTCONTROLLER|0x01)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x3F))) //End horizontal display updated?
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		tempdata = VGA->registers->CRTControllerRegisters.REGISTERS.ENDHORIZONTALDISPLAYREGISTER;
		++tempdata; //Stop after this character!
		tempdata *= VGA->precalcs.characterwidth; //Original!
		tempdata <<= et34kdata->doublehorizontaltimings; //Double the horizontal timings if needed!
		//dolog("VGA","HDispEnd updated: %u",hdispend);
		//dolog("VGA","VTotal after: %u",VGA->precalcs.verticaltotal); //Log it!
		if (VGA->precalcs.horizontaldisplayend != tempdata) adjustVGASpeed(); //Update our speed!
		updateCRTC |= (VGA->precalcs.horizontaldisplayend != tempdata); //Update!
		VGA->precalcs.horizontaldisplayend = tempdata; //Load!
	}

	if (CRTUpdated || horizontaltimingsupdated || CRTUpdatedCharwidth || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x3F)) //Extended bits of the overflow register!
		//Finally, bits needed by the overflow register itself(of which we are an extension)!
		|| (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x2)) //Horizontal blank start
		)
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif

		word hblankstart;
		//bit2=Horizontal blanking bit 8
		hblankstart = VGA->registers->CRTControllerRegisters.REGISTERS.STARTHORIZONTALBLANKINGREGISTER;
		hblankstart |= ((et34k_tempreg & 4) << 6); //Add/replace the new/changed bits!
		++hblankstart; //Start after this character!
		VGA->precalcs.horizontalblankingstartfinish = hblankstart;
		hblankstart *= VGA->precalcs.characterwidth;
		//dolog("VGA","HBlankStart updated: %u",hblankstart);
		//dolog("VGA","VTotal after: %u",VGA->precalcs.verticaltotal); //Log it!
		hblankstart <<= et34kdata->doublehorizontaltimings; //Double the horizontal timings if needed!
		if (VGA->precalcs.horizontalblankingstart != hblankstart) adjustVGASpeed(); //Update our speed!
		updateCRTC |= (VGA->precalcs.horizontalblankingstart != hblankstart); //Update!
		VGA->precalcs.horizontalblankingstart = hblankstart; //Load!
		hblankstart = VGA->precalcs.horizontalblankingstartfinish;
		++hblankstart; //End after this character!
		hblankstart *= VGA->precalcs.characterwidth;
		//dolog("VGA","HBlankStart updated: %u",hblankstart);
		//dolog("VGA","VTotal after: %u",VGA->precalcs.verticaltotal); //Log it!
		hblankstart <<= et34kdata->doublehorizontaltimings; //Double the horizontal timings if needed!
		VGA->precalcs.horizontalblankingstartfinish = hblankstart; //Load!
	}

	if (CRTUpdated || horizontaltimingsupdated || CRTUpdatedCharwidth || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x3F)) //Extended bits of the overflow register!
		//Finally, bits needed by the overflow register itself(of which we are an extension)!
		|| (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x4)) //Horizontal retrace start
		)
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		//bit4=Horizontal retrace bit 8
		tempdata = VGA->registers->CRTControllerRegisters.REGISTERS.STARTHORIZONTALRETRACEREGISTER;
		tempdata |= ((et34k_tempreg & 0x10) << 4); //Add the new/changed bits!
		tempdata += GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.ENDHORIZONTALRETRACEREGISTER,5,0x3); //Add skew!
		//++tempdata; //One later!
		VGA->precalcs.horizontalretracestartfinish = tempdata; //Finish on the next clock?
		tempdata *= VGA->precalcs.characterwidth; //We're character units!
		tempdata <<= et34kdata->doublehorizontaltimings; //Double the horizontal timings if needed!
		updateCRTC |= VGA->precalcs.horizontalretracestart != tempdata; //To be updated?
		VGA->precalcs.horizontalretracestart = tempdata; //Save the new data!
		tempdata = VGA->precalcs.horizontalretracestartfinish; //When to finish?
		++tempdata; //The next clock is when we finish!
		tempdata *= VGA->precalcs.characterwidth; //We're character units!
		tempdata <<= et34kdata->doublehorizontaltimings; //Double the horizontal timings if needed!
		updateCRTC |= VGA->precalcs.horizontalretracestartfinish != tempdata; //To be updated?
		VGA->precalcs.horizontalretracestartfinish = tempdata; //Save the new data!
	}
	if (CRTUpdated || horizontaltimingsupdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x3F)) //Extended bits of the overflow register!
		//Finally, bits needed by the overflow register itself(of which we are an extension)!
		|| (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x13)) //Offset register
		)
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		//bit7=Offset bit 8
		tempdata = VGA->registers->CRTControllerRegisters.REGISTERS.OFFSETREGISTER; //The offset to use!
		updateCRTC |= (((et34k_tempreg & 0x80) << 1) | (tempdata & 0xFF)) != tempdata; //To be updated?
		tempdata |= ((et34k_tempreg & 0x80) << 1); //Add/replace the new/changed bits!
		tempdata <<= et34kdata->doublehorizontaltimings; //Double the horizontal timings if needed!
		tempdata <<= 1; //Reapply the x2 multiplier that's required!
		VGA->precalcs.rowsize = tempdata; //Save the new data!
	}
	if (CRTUpdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x34)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x31)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x24)) || (whereupdated==(WHEREUPDATED_SEQUENCER|0x07))) //Clock frequency might have been updated?
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		if (VGA==getActiveVGA()) //Active VGA?
		{
			changeRowTimer(VGA); //Make sure the display scanline refresh rate is OK!
		}		
	}

	//Misc settings
	if (CRTUpdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x36))
		|| (whereupdated==(WHEREUPDATED_SEQUENCER|0x4)) || (whereupdated==(WHEREUPDATED_GRAPHICSCONTROLLER|0x5)) //Memory address
		 ) //Video system configuration #1!
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		et34k_tempreg = et4k_reg(et34kdata, 3d4, 36); //The overflow register!
		tempval = VGA->precalcs.linearmode; //Old val!
		if (VGA->enable_SVGA==2) //Special ET3000 mapping?
		{
			VGA->precalcs.linearmode &= ~3; //Use normal Bank Select Register with VGA method of access!
			switch (et34k(VGA)->bank_size&3) //What Bank setting are we using?
			{
				case 0: //128k segments?
					VGA_MemoryMapBankRead = et34kdata->bank_read<<17; //Read bank!
					VGA_MemoryMapBankWrite = et34kdata->bank_write<<17; //Write bank!
					break;
				case 2: //1M linear memory?
				case 3: //1M linear memory? Unverified!
					VGA->precalcs.linearmode |= 1; //Use contiguous memory accessing!
					//Same memory banking is used! 64k banks!
				case 1: //64k segments?
					VGA_MemoryMapBankRead = et34kdata->bank_read<<16; //Read bank!
					VGA_MemoryMapBankWrite = et34kdata->bank_write<<16; //Write bank!
					break;
				default:
					break;
			}
			VGA->precalcs.linearmode |= 4; //Enable the new linear and contiguous modes to affect memory!
		}
		else //ET4000 mapping?
		{
			if ((et34k_tempreg & 0x10)==0x00) //Segment configuration?
			{
				VGA_MemoryMapBankRead = et34kdata->bank_read<<16; //Read bank!
				VGA_MemoryMapBankWrite = et34kdata->bank_write<<16; //Write bank!
				VGA->precalcs.linearmode &= ~2; //Use normal data addresses!
			}
			else //Linear system configuration? Disable the segment and enable linear mode (high 4 bits of the address select the bank)!
			{
				VGA_MemoryMapBankRead = 0; //No read bank!
				VGA_MemoryMapBankWrite = 0; //No write bank!
				VGA->precalcs.linearmode |= 2; //Linear mode, use high 4-bits!
			}
			if (et34k_tempreg & 0x20) //Continuous memory?
			{
				VGA->precalcs.linearmode |= 1; //Enable contiguous memory!
			}
			else //Normal memory addressing?
			{
				VGA->precalcs.linearmode &= ~1; //Use VGA-mapping of memory!
			}
			VGA->precalcs.linearmode |= 4; //Enable the new linear and contiguous modes to affect memory!
		}

		linearmodeupdated = (tempval!=VGA->precalcs.linearmode); //Linear mode has been updated!

		if ((VGA->precalcs.linearmode&5)==5) //Special ET3K/ET4K linear graphics memory mode?
		{
			VGA_ReadMemoryMode = VGA_WriteMemoryMode = 3; //Special ET3000/ET4000 linear graphics memory mode!
		}
		else //Normal VGA memory access?
		{
			VGA_ReadMemoryMode = VGA->precalcs.ReadMemoryMode; //VGA compatibility mode!
			VGA_WriteMemoryMode = VGA->precalcs.WriteMemoryMode; //VGA compatiblity mode!
		}
		updateVGAMMUAddressMode(); //Update the currently assigned memory mode for mapping memory by address!

		newfontwidth = ((et34k_tempreg & 4) >> 2); //Are we to use 16-bit wide fonts?
		if (unlikely(VGA->precalcs.doublewidthfont != newfontwidth)) //Font width is changed?
		{
			VGA->precalcs.doublewidthfont = newfontwidth; //Apply double font width or not!
			VGA_charsetupdated(VGA); //Update the character set, as a new width is to be applied!
		}
	}

	if (CRTUpdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_SEQUENCER | 0x04)) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x37))
		) //Video system configuration #2?
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		VGA->precalcs.VMemMask = VGA->precalcs.VRAMmask&et34kdata->memwrap; //Apply the SVGA memory wrap on top of the normal memory wrapping!
	}

	if ((whereupdated==WHEREUPDATED_ALL) || (whereupdated==WHEREUPDATED_DACMASKREGISTER) || //DAC Mask register has been updated?
		(AttrUpdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_ATTRIBUTECONTROLLER | 0x16)) || (whereupdated == (WHEREUPDATED_ATTRIBUTECONTROLLER | 0x10))) //Attribute misc. register?
		|| (
			(et34k(VGA)->emulatedDAC == 2) //AT&T 20C490?
			&& UPDATE_SECTIONFULL(whereupdated, WHEREUPDATED_DAC, FullUpdate) //Single register updated?
			&& (et34k(VGA)->hicolorDACcommand&1) //Supposed to be masked off?
			)
		) 
	{
		#ifdef LOG_UNHANDLED_SVGA_ACCESSES
		handled = 1;
		#endif
		et34k_tempreg = et34k(VGA)->hicolorDACcommand; //Load the command to process! (Process like a SC11487)
		VGA->precalcs.SC15025_pixelmaskregister = ~0; //Default: no filter!
		DACmode = VGA->precalcs.DACmode; //Load the current DAC mode!
		DACmode &= ~8; //Legacy DAC modes?
		if ((et34k(VGA)->emulatedDAC!=2) && (et34k(VGA)->emulatedDAC<3)) //UMC UM70C178 or SC11487?
		{
			if (VGA->precalcs.AttributeController_16bitDAC == 3) //In 16-bit mode? Raise the DAC's HICOL input, thus making it 16-bit too!
			{
				//DACmode |= 3; //Set bit 0: we're full range, Set bit 1: we're a 16-bit mode!
				goto legacyDACmode; //Let the DAC determine what mode it's in normally!
			}
			else //Legacy DAC mode? Use the DAC itself for determining the mode it's rendering in!
			{
				legacyDACmode:
				if ((et34k_tempreg & 0xC0) == 0x80) //15-bit hicolor mode?
				{
					DACmode &= ~1; //Clear bit 0: we're one bit less!
					DACmode |= 2; //Set bit 1: we're a 16-bit mode!
				}
				else if ((et34k_tempreg & 0xC0) == 0xC0) //16-bit hicolor mode?
				{
					DACmode |= 3; //Set bit 0: we're full range, Set bit 1: we're a 16-bit mode!
				}
				else //Normal 8-bit DAC?
				{
					DACmode &= ~3; //Set bit 0: we're full range, Set bit 1: we're a 16-bit mode!
				}
			}
			if (et34k_tempreg & 0x20) //Two pixel clocks are used to latch the two bytes?
			{
				DACmode |= 4; //Use two pixel clocks to latch the two bytes?
			}
			else
			{
				DACmode &= ~4; //Use one pixel clock to latch the two bytes?
			}
		}
		else if (et34k(VGA)->emulatedDAC==2) //AT&T 20C490?
		{
			DACmode = 0; //Legacy VGA RAMDAC!
			VGA->precalcs.emulatedDACextrabits = 0xC0; //Become 8-bits DAC entries by default!
			switch ((et34k_tempreg>>5)&7) //What rendering mode?
			{
				case 0:
				case 1:
				case 2:
				case 3: //VGA mode?
					if ((et34k_tempreg & 2)==0) //6-bit DAC?
					{
						VGA->precalcs.emulatedDACextrabits = 0x00; //Become 6-bits DAC only!
					}
					break;
				case 4: //15-bit HICOLOR1 one clock?
					DACmode &= ~1; //Clear bit 0: we're one bit less!
					DACmode |= 2; //Set bit 1: we're a 16-bit mode!
					DACmode &= ~4; //Use one pixel clock to latch the two bytes?
					break;
				case 5: //15-bit HICOLOR2 two clocks?
					DACmode &= ~1; //Clear bit 0: we're one bit less!
					DACmode |= 2; //Set bit 1: we're a 16-bit mode!
					DACmode |= 4; //Use two pixel clocks to latch the two bytes?
					break;
				case 6: //16-bit two clocks?
					DACmode |= 3; //Set bit 0: we're full range, Set bit 1: we're a 16-bit mode!
					DACmode |= 4; //Use two pixel clocks to latch the two bytes?
					break;
				case 7: //24-bit three clocks?
					DACmode |= 3; //Set bit 0: we're full range, Set bit 1: we're a 16-bit+ mode!
					DACmode |= 4; //Use multiple pixel clocks to latch the two bytes?
					DACmode |= 8; //Use three pixel clocks to latch the three bytes?
					break;
			}

			//Update the DAC colors as required!
			if (et34k_tempreg & 1) //Sleep mode?
			{
				VGA->precalcs.turnDACoff = 1; //Turn the DAC off!
			}
			else
			{
				VGA->precalcs.turnDACoff = 0; //Turn the DAC on!
			}

			int colorval;
			colorval = 0; //Init!
			for (;;) //Precalculate colors for DAC!
			{
				if (VGA->enable_SVGA != 3) //EGA can't change the DAC!
				{
					VGA->precalcs.DAC[colorval] = getcol256_Tseng(VGA, colorval); //Translate directly through DAC for output!
				}
				DAC_updateEntry(VGA, colorval); //Update a DAC entry for rendering!
				if (++colorval & 0xFF00) break; //Overflow?
			}
		}
		else if (et34k(VGA)->emulatedDAC == 3) //SC15025?
		{
			DACmode = 0; //Legacy VGA RAMDAC! Bit 5 is 32-bit color, otherwise 24-bit color! Bit 6 is translation mode enabled!
			if (et34k(VGA)->SC15025_auxiliarycontrolregister&4) //Sleep mode? Undocumented!
			{
				VGA->precalcs.turnDACoff = 1; //Turn the DAC off!
			}
			else
			{
				VGA->precalcs.turnDACoff = 0; //Turn the DAC on!
			}
			//Bit 1 of the Auxiliary Control Register is PED 75 IRE? Unknown what this is?
			VGA->precalcs.emulatedDACextrabits = 0xC0; //Become 8-bits DAC entries by default!
			if ((et34k(VGA)->SC15025_pixelrepackregister & 1) == 0) //6-bit DAC?
			{
				VGA->precalcs.emulatedDACextrabits = 0x00; //Become 6-bits DAC only!
			}
			VGA->precalcs.SC15025_pixelmaskregister = ((((et34k(VGA)->SC15025_secondarypixelmaskregisters[2]<<8)|et34k(VGA)->SC15025_secondarypixelmaskregisters[1])<<8)|et34k(VGA)->SC15025_secondarypixelmaskregisters[0]); //Pixel mask to use!
			et34k(VGA)->SC15025_enableExtendedRegisters = ((et34k_tempreg & 0x10) >> 4); //Enable the extended registers at the color registers?
			switch ((et34k_tempreg >> 5) & 7) //What rendering mode?
			{
			case 0:
			case 1: //VGA mode? Mode 0!
				break;
			case 2:  //Mode 3a without bit 0 of the pixel repack register! VGA otherwise!
				if (et34k(VGA)->SC15025_pixelrepackregister & 1) //Mode 3a?
				{
					DACmode |= 3; //Set bit 0: we're full range, Set bit 1: we're a 16-bit+ mode!
					DACmode |= 4; //Use multiple pixel clocks to latch the two bytes?
					DACmode |= 8; //Use three pixel clocks to latch the three bytes?
					DACmode |= 0x10; //Use four pixel clocks to latch the three bytes?
					if ((et34k_tempreg & 1)==0) //RGB mode?
					{
						DACmode |= 0x20; //RGB mode is enabled!
					}
					if (et34k_tempreg & 0x8) //D3 set? Enable LUT mode!
					{
						DACmode |= 0x40; //Enable LUT!
						DACmode |= ((et34k_tempreg & 0x6) << 6); //Bits 6&7 are to shift in 
					}
				}
				//Otherwise, VGA? Mode 0!
				break;
			case 3: //Mode 2 or 3b?
				if (et34k(VGA)->SC15025_pixelrepackregister & 1) //Mode 3b?
				{
					DACmode |= 3; //Set bit 0: we're full range, Set bit 1: we're a 16-bit+ mode!
					DACmode |= 4; //Use multiple pixel clocks to latch the two bytes?
					DACmode |= 8; //Use three pixel clocks to latch the three bytes?
					DACmode |= 0x10; //Use four pixel clocks to latch the three bytes instead!
					if ((et34k_tempreg & 1)==0) //RGB mode?
					{
						DACmode |= 0x20; //RGB mode is enabled!
					}
					if (et34k_tempreg & 0x8) //D3 set? Enable LUT mode!
					{
						DACmode |= 0x40; //Enable LUT!
						DACmode |= ((et34k_tempreg & 0x6) << 6); //Bits 6&7 are to shift in 
					}
				}
				else //Mode 2? 3-byte mode!
				{
					DACmode |= 3; //Set bit 0: we're full range, Set bit 1: we're a 16-bit+ mode!
					DACmode |= 4; //Use multiple pixel clocks to latch the two bytes?
					DACmode |= 8; //Use three pixel clocks to latch the three bytes?
					if (et34k_tempreg & 0x8) //D3 set? Enable LUT mode!
					{
						DACmode |= 0x40; //Enable LUT!
						DACmode |= ((et34k_tempreg & 0x6) << 6); //Bits 6&7 are to shift in 
					}
				}
				break;
			case 4: //15-bit HICOLOR1 one clock? Mode 1&2! 2 when D0 is set, color mode 1 otherwise! Repack mode 1a!
				DACmode |= 0x200; //Bit 15 is sent as well!
				DACmode &= ~1; //Clear bit 0: we're one bit less!
				DACmode |= 2; //Set bit 1: we're a 16-bit mode!
				DACmode &= ~4; //Use one pixel clock to latch the two bytes?
				if (et34k_tempreg & 1) //Extended mode? Color Mode 2!
				{
					DACmode |= 0x20; //Extended mode is enabled!
				}
				if (et34k_tempreg & 0x8) //D3 set? Enable LUT mode!
				{
					DACmode |= 0x40; //Enable LUT!
					DACmode |= ((et34k_tempreg & 0x6) << 6); //Bits 6&7 are to shift in 
				}
				//Otherwise, Color Mode 1?
				break;
			case 5: //15-bit HICOLOR2 two clocks? Color Mode 1&2! 2 when D0 is set! Repack mode 1b!
				DACmode |= 0x200; //Bit 15 is sent as well!
				DACmode &= ~1; //Clear bit 0: we're one bit less!
				DACmode |= 2; //Set bit 1: we're a 16-bit mode!
				DACmode |= 4; //Use two pixel clocks to latch the two bytes?
				if (et34k_tempreg & 1) //Extended mode? Mode 2!
				{
					DACmode |= 0x20; //Extended mode is enabled!
				}
				if (et34k_tempreg & 0x8) //D3 set? Enable LUT mode!
				{
					DACmode |= 0x40; //Enable LUT!
					DACmode |= ((et34k_tempreg & 0x6) << 6); //Bits 6&7 are to shift in 
				}
				//Othereise, color Mode 1?
				break;
			case 6: //16-bit one clock? Color Mode 3! Repack mode 1a!
				DACmode |= 3; //Set bit 0: we're full range, Set bit 1: we're a 16-bit mode!
				DACmode &= ~4; //Use one pixel clock to latch the two bytes?
				if (et34k_tempreg & 0x8) //D3 set? Enable LUT mode!
				{
					DACmode |= 0x40; //Enable LUT!
					DACmode |= ((et34k_tempreg & 0x6) << 6); //Bits 6&7 are to shift in 
				}
				break;
			case 7: //16-bit two clocks? Color Mode 3! Repack mode 1b!
				DACmode |= 3; //Set bit 0: we're full range, Set bit 1: we're a 16-bit+ mode!
				DACmode |= 4; //Use multiple pixel clocks to latch the two bytes?
				if (et34k_tempreg & 0x8) //D3 set? Enable LUT mode!
				{
					DACmode |= 0x40; //Enable LUT!
					DACmode |= ((et34k_tempreg & 0x6) << 6); //Bits 6&7 are to shift in 
				}
				break;
			}
		}
		else //Unknown DAC?
		{
			DACmode = 0; //Legacy VGA RAMDAC!
		}
		VGA->precalcs.DACmode = DACmode; //Apply the new DAC mode!
		updateVGADAC_Mode(VGA); //Update the effective DAC mode!
		updateSequencerPixelDivider(VGA, (SEQ_DATA*)VGA->Sequencer); //Update the sequencer as well!
		updateVGAAttributeController_Mode(VGA); //Update the attribute mode!
	}

	if (SequencerUpdated || AttrUpdated || (whereupdated==(WHEREUPDATED_ATTRIBUTECONTROLLER|0x10)) || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_GRAPHICSCONTROLLER | 0x05)) || (whereupdated == (WHEREUPDATED_SEQUENCER | 0x04)) || linearmodeupdated
		) //Attribute misc. register?
	{
		et34k_tempreg = VGA->precalcs.linearmode; //Save the old mode for reference!
		VGA->precalcs.linearmode = ((VGA->precalcs.linearmode&~8) | (VGA->registers->SequencerRegisters.REGISTERS.SEQUENCERMEMORYMODEREGISTER&8)); //Linear graphics mode special actions enabled? Ignore Read Plane Select and Write Plane mask if set!
		VGA->precalcs.linearmode = ((VGA->precalcs.linearmode&~0x10) | ((VGA->registers->GraphicsRegisters.REGISTERS.GRAPHICSMODEREGISTER&0x40)>>2)); //Linear graphics mode for the renderer enabled?
		if (VGA->registers->AttributeControllerRegisters.REGISTERS.ATTRIBUTEMODECONTROLREGISTER & 0x40) //8-bit mode is setup?
		{
			VGA->precalcs.linearmode &= ~0x18; //Disable the linear mode override and use compatibility with the VGA!
		}

		linearmodeupdated = (VGA->precalcs.linearmode != et34k_tempreg); //Are we updating the mode?
		updateCRTC |= (VGA->precalcs.linearmode != et34k_tempreg); //Are we to update modes?

		if ((VGA->precalcs.linearmode & 0x10) || GETBITS(VGA->registers->AttributeControllerRegisters.REGISTERS.ATTRIBUTEMODECONTROLREGISTER, 6, 1)) //8-bit rendering has been enabled either through the Attribute Controller or mode set?
		{
			VGA->precalcs.AttributeModeControlRegister_ColorEnable8Bit = (VGA->precalcs.linearmode & 0x10)?3:1; //Enable 8-bit graphics!
			updateVGAAttributeController_Mode(VGA); //Update the attribute controller!
		}
		else
		{
			VGA->precalcs.AttributeModeControlRegister_ColorEnable8Bit = 0; //Disable 8-bit graphics!
			updateVGAAttributeController_Mode(VGA); //Update the attribute controller!
		}
	}

	if (CRTUpdated || charwidthupdated || (whereupdated==(WHEREUPDATED_CRTCONTROLLER|0x14))
		|| (whereupdated==(WHEREUPDATED_CRTCONTROLLER|0x17))
		|| SequencerUpdated || AttrUpdated || (whereupdated==(WHEREUPDATED_ATTRIBUTECONTROLLER|0x10)) || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_GRAPHICSCONTROLLER | 0x05)) || linearmodeupdated
		) //Updated?
	{
		//This applies to the Frame buffer:
		byte BWDModeShift = 1; //Default: word mode!
		if (GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.UNDERLINELOCATIONREGISTER,6,1))
		{
			BWDModeShift = 2; //Shift by 2!
		}
		else if (GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.CRTCMODECONTROLREGISTER,6,1))
		{
			BWDModeShift = 0; //Shift by 0! We're byte mode!
		}

		byte characterclockshift = 1; //Default: reload every whole clock!
		//This applies to the address counter (renderer), causing it to increase and load more/less(factors of 2). This is used as a mask to apply to the 
		if (GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.UNDERLINELOCATIONREGISTER,5,1))
		{
			if (GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.CRTCMODECONTROLREGISTER,3,1)) //Both set? We reload twice per clock!
			{
				characterclockshift = 0; //Reload every half clock(4 pixels)!
			}
			else //Reload every 4 clocks!
			{
				characterclockshift = 7; //Reload every 4 clocks(32 pixels)!
			}
		}
		else if (GETBITS(VGA->registers->CRTControllerRegisters.REGISTERS.CRTCMODECONTROLREGISTER,3,1))
		{
			characterclockshift = 3; //Reload every other clock(16 pixels)!
		}
		else //Reload every clock!
		{
			characterclockshift = 1; //Reload every whole clock(8 pixels)!
		}

		if (VGA->precalcs.linearmode&0x10) //Linear mode is different on Tseng chipsets? This activates byte mode!
		{
			BWDModeShift = 0; //Byte mode always! We're linear memory, so act that way!
			characterclockshift = ((characterclockshift << 1) | 1); //Double the programmed character clock: two times the normal data is processed!
		}

		updateCRTC |= (VGA->precalcs.BWDModeShift != BWDModeShift); //Update the CRTC!
		VGA->precalcs.BWDModeShift = BWDModeShift;

		updateCRTC |= (VGA->precalcs.characterclockshift != characterclockshift); //Update the CRTC!
		VGA->precalcs.characterclockshift = characterclockshift; //Apply character clock shift!

		//dolog("VGA","VTotal after VRAMMemAddrSize: %u",VGA->precalcs.verticaltotal); //Log it!
	}

	if (((whereupdated==(WHEREUPDATED_SEQUENCER|0x01)) || FullUpdate || !VGA->precalcs.characterwidth) || (VGA->precalcs.charwidthupdated) //Sequencer register updated?
		|| (SequencerUpdated || AttrUpdated || (whereupdated==(WHEREUPDATED_ATTRIBUTECONTROLLER|0x10)) || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_SEQUENCER | 0x04)))
		|| ((whereupdated==(WHEREUPDATED_SEQUENCER|0x06)))
		//Double width font updated is checked below?
		|| (CRTUpdated || (whereupdated == WHEREUPDATED_ALL) || (whereupdated == (WHEREUPDATED_CRTCONTROLLER | 0x36))
			|| (whereupdated == (WHEREUPDATED_GRAPHICSCONTROLLER | 0x5)) //Memory address
			)
		|| linearmodeupdated
		)
	{
		if (VGA->precalcs.ClockingModeRegister_DCR != et34k_tempreg) adjustVGASpeed(); //Auto-adjust our VGA speed!
		et34k_tempreg = (GETBITS(VGA->registers->SequencerRegisters.REGISTERS.CLOCKINGMODEREGISTER,3,1))|((VGA->precalcs.linearmode&0x10)>>3); //Dot Clock Rate!
		if (VGA->enable_SVGA == 2) //ET3000 seems to oddly provide the DCR in bit 2 sometimes?
		{
			et34k_tempreg |= GETBITS(VGA->registers->SequencerRegisters.REGISTERS.CLOCKINGMODEREGISTER, 1, 1); //Use bit 1 as well!
		}
		updateCRTC |= (VGA->precalcs.ClockingModeRegister_DCR != et34k_tempreg); //Update the CRTC!
		VGA->precalcs.ClockingModeRegister_DCR = et34k_tempreg;

		et34k_tempreg = et34k_reg(et34kdata, 3c4, 06); //TS State Control
		et34k_tempreg &= 0x06; //Only bits 1-2 are used!
		if (VGA->precalcs.doublewidthfont == 0) //Double width not enabled? Then we're invalid(VGA-compatible)!
		{
			et34k_tempreg = 0; //VGA-compatible!
		}
		et34k_tempreg |= GETBITS(VGA->registers->SequencerRegisters.REGISTERS.CLOCKINGMODEREGISTER, 0, 1); //Bit 0 of the Clocking Mode Register(Tseng calls it the TS Mode register) is also included!
		switch (et34k_tempreg) //What extended clocking mode?
		{
		default:
		case 0: //VGA-compatible modes?
		case 1: //VGA-compatible modes?
			newcharwidth = GETBITS(VGA->registers->SequencerRegisters.REGISTERS.CLOCKINGMODEREGISTER, 0, 1) ? 8 : 9; //Character width!
			newtextwidth = VGA->precalcs.characterwidth; //Text character width(same as normal characterwidth by default)!
			break;
		case 2: //10 dots/char?
		case 3: //11 dots/char?
		case 4: //12 dots/char?
			newcharwidth = 8; //Character width!
			newtextwidth = (8|et34k_tempreg); //Text character width!
			break;
		case 5: //WhatVGA says 7 dots/char!
		case 6: //WhatVGA says 6 dots/char!
			newcharwidth = 8; //Character width!
			newtextwidth = (6 | (et34k_tempreg&1)); //Text character width!
			break;
		case 7: //16 dots/char?
			newcharwidth = 8; //Character width!
			newtextwidth = 16; //Text character width!
			break;
		}
		updateCRTC |= (VGA->precalcs.characterwidth != newcharwidth); //Char width updated?
		updateCRTC |= (VGA->precalcs.textcharacterwidth != newtextwidth); //Char width updated?
		VGA->precalcs.characterwidth = newcharwidth; //Char clock width!
		VGA->precalcs.textcharacterwidth = newtextwidth; //Text character width!
	}

	if (updateCRTC) //Update CRTC?
	{
		VGA_calcprecalcs_CRTC(VGA); //Update the CRTC timing data!
		adjustVGASpeed(); //Auto-adjust our VGA speed!
	}

	VGA->precalcs.charwidthupdated = 0; //Not updated anymore!
	et34k(VGA)->oldextensionsEnabled = et34k(VGA)->extensionsEnabled; //Save the new extension status to detect changes!
	#ifdef LOG_UNHANDLED_SVGA_ACCESSES
	if (!handled) //Are we not handled?
	{
		dolog("ET34k","Unandled precalcs on SVGA: %08X",whereupdated); //We're ignored!
	}
	#endif
}

DOUBLE Tseng34k_clockMultiplier(VGA_Type *VGA)
{
	byte timingdivider = et34k_reg(et34k(VGA),3c4,07); //Get the divider info!
	if (timingdivider&0x01) //Divide Master Clock Input by 4!
	{
		#ifdef IS_LONGDOUBLE
		return 0.25L; //Divide by 4!
		#else
		return 0.25; //Divide by 4!
		#endif
	}
	else if (timingdivider&0x40) //Divide Master Clock Input by 2!
	{
		#ifdef IS_LONGDOUBLE
		return 0.5L; //Divide by 2!
		#else
		return 0.5; //Divide by 2!
		#endif
	}
	//Normal Master clock?
	#ifdef IS_LONGDOUBLE
	return 1.0L; //Normal clock!
	#else
	return 1.0; //Normal clock!
	#endif
}

extern DOUBLE VGA_clocks[4]; //Normal VGA clocks!

DOUBLE Tseng34k_getClockRate(VGA_Type *VGA)
{
	byte clock_index;
	if (!et34k(VGA)) return 0.0f; //Unregisterd ET4K!
	if (VGA->enable_SVGA == 2) //ET3000?
	{
		clock_index = get_clock_index_et3k(VGA); //Retrieve the ET4K clock index!
		//if (clock_index<2) return VGA_clocks[clock_index]*Tseng34k_clockMultiplier(VGA); //VGA-compatible clocks!
		return ET3K_clockFreq[clock_index & 0xF]*Tseng34k_clockMultiplier(VGA); //Give the ET4K clock index rate!
	}
	else //ET4000?
	{
		clock_index = get_clock_index_et4k(VGA); //Retrieve the ET4K clock index!
		//if (clock_index<2) return VGA_clocks[clock_index]*Tseng34k_clockMultiplier(VGA); //VGA-compatible clocks!
		return ET4K_clockFreq[clock_index & 0xF]*Tseng34k_clockMultiplier(VGA); //Give the ET4K clock index rate!
	}
	return 0.0; //Not an ET3K/ET4K clock rate, default to VGA rate!
}

void SVGA_Setup_TsengET4K(uint_32 VRAMSize) {
	if ((getActiveVGA()->enable_SVGA == 2) || (getActiveVGA()->enable_SVGA == 1)) //ET3000/ET4000?
		VGA_registerExtension(&Tseng34K_readIO, &Tseng34K_writeIO, &Tseng34k_init,&Tseng34k_calcPrecalcs,&Tseng34k_getClockRate,NULL);
	else return; //Invalid SVGA!		
	Tseng4k_VRAMSize = VRAMSize; //Set this VRAM size to use!
	getActiveVGA()->SVGAExtension = zalloc(sizeof(SVGA_ET34K_DATA),"SVGA_ET34K_DATA",getLock(LOCK_CPU)); //Our SVGA extension data!
	if (!getActiveVGA()->SVGAExtension)
	{
		raiseError("ET4000","Couldn't allocate SVGA card ET4000 data! Ran out of memory!");
	}
	else //Valid registers?
	{
		et34k_reg(et34k(getActiveVGA()),3c4,07) = 0x4|0x8|0x20|0x80; //Default to VGA mode with full memory map, Other bits are set always.
	}
}
