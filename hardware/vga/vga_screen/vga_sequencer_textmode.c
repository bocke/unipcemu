#define VGA_SEQUENCER_TEXTMODE

#include "headers/hardware/vga.h" //Our typedefs etc!
#include "headers/hardware/vga_screen/vga_attributecontroller.h" //Attribute controller for typedef of attribute info!
#include "headers/hardware/vga_screen/vga_crtcontroller.h" //CRT Controller!
#include "headers/hardware/vga_screen/vga_vram.h" //Our VRAM support!
#include "headers/hardware/vga_screen/vga_vramtext.h" //Our VRAM text support!
#include "headers/hardware/vga_screen/vga_precalcs.h" //Precalculation typedefs etc.
#include "headers/support/log.h" //Logging support!
#include "headers/hardware/vga_screen/vga_sequencer.h" //Sequencer!

OPTINLINE uint_32 getcursorlocation(VGA_Type *VGA) //Location of the cursor!
{
	return VGA->precalcs.cursorlocation; //Cursor location!
}

//Character is cursor position?
#define CHARISCURSOR (Sequencer_textmode_charindex==getcursorlocation(VGA))
//Scanline is cursor position?
#define SCANLINEISCURSOR1 (Rendery>=VGA->registers->CRTControllerRegisters.REGISTERS.CURSORSTARTREGISTER.CursorScanLineStart)
#define SCANLINEISCURSOR2 (Rendery<=VGA->registers->CRTControllerRegisters.REGISTERS.CURSORENDREGISTER.CursorScanLineEnd)
//Cursor is enabled atm?
#define CURSORENABLED1 (!VGA->registers->CRTControllerRegisters.REGISTERS.CURSORSTARTREGISTER.CursorDisable)
#define CURSORENABLED2 (VGA->CursorOn)

OPTINLINE byte is_cursorscanline(VGA_Type *VGA,byte Rendery,uint_32 Sequencer_textmode_charindex) //Cursor scanline within character is cursor? Used to be: VGA_Type *VGA, byte ScanLine,uint_32 characterlocation
{
	if (CHARISCURSOR) //Character is cursor?
	{
		if (CURSORENABLED1) //Cursor enabled?
		{
			if (CURSORENABLED2) //Cursor on?
			{
				if (SCANLINEISCURSOR1 && SCANLINEISCURSOR2) //Scanline is cursor top&bottom?
				{
					return 1; //To show the cursor on this scanline?
				}
			}
		}
	}
	return 0; //No cursor!
}

void VGA_Sequencer_TextMode_updateRow(VGA_Type *VGA, SEQ_DATA *Sequencer)
{
	register word row;
	register uint_32 charystart;
	row = Sequencer->Scanline; //Default: our normal scanline!
	row >>= VGA_ScanDoubling(VGA); //Apply Scan Doubling here: we take effect on content!
	row <<= 1; //We're always a multiple of 2 by index into charrowstatus!

	//Row now is an index into charrowstatus
	word *currowstatus = &VGA->CRTC.charrowstatus[row]; //Current row status!
	Sequencer->chary = row = *currowstatus++; //First is chary (effective character/graphics row)!
	Sequencer->charinner_y = *currowstatus; //Second is charinner_y!
	
	charystart = getVRAMScanlineStart(VGA,row); //Calculate row start!
	charystart += Sequencer->startmap; //Calculate the start of the map while we're at it: it's faster this way!
	charystart += Sequencer->bytepanning; //Apply byte panning to the index!
	Sequencer->charystart = charystart; //What row to start with our pixels!

	//Some attribute controller special 8-bit mode support!
	Sequencer->doublepixels = 0; //Reset double pixels status for odd sized screens.
}

void VGA_Sequencer_TextMode(VGA_Type *VGA, SEQ_DATA *Sequencer, VGA_AttributeInfo *attributeinfo) //Render a text mode pixel!
{
	//First, full value to lookup!
	register word character;
	register word charinner;
	register byte pixel;
	word *curcolstatus;
	byte currentchar, attribute;
	character = Sequencer->activex; //Current character point (horizontally)
	//X!
	character >>= VGA->registers->CRTControllerRegisters.REGISTERS.CRTCMODECONTROLREGISTER.DIV2; //Apply DIVIDE by 2 when needed!
	character <<= 1; //The index into charcolstatus is always a multiple of 2!

	curcolstatus = &VGA->CRTC.charcolstatus[character]; //Current col status!
	attributeinfo->charx = character = *curcolstatus++; //First is charx!
	attributeinfo->charinner_x = charinner = *curcolstatus; //Second is charinner_y!

	character <<= getVGAShift(VGA); //Calculate the index into the current row!
	
	character += Sequencer->charystart; //Add the start of the row!

	currentchar = readVRAMplane(VGA,0,character,1); //The character itself! From plane 0!
	attribute = readVRAMplane(VGA,1,character,1); //The attribute itself! From plane 1!
	
	pixel = getcharxy(VGA,attribute,currentchar,(byte)charinner,(byte)Sequencer->charinner_y); //Check for the character, the simple way!
	pixel |= is_cursorscanline(VGA,(byte)Sequencer->charinner_y,character); //Get if we're to plot font, include cursor? (Else back) Used to be: VGA,attributeinfo->charinner_y,charindex
	attributeinfo->fontpixel = pixel; //We're the font pixel?
	attributeinfo->attribute = attribute; //The attribute for this pixel!
}