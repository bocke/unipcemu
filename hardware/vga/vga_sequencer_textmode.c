#define VGA_SEQUENCER_TEXTMODE

#include "headers/hardware/vga/vga.h" //Our typedefs etc!
#include "headers/hardware/vga/vga_vramtext.h" //Our VRAM text support!
#include "headers/hardware/vga/vga_sequencer.h" //Sequencer!
#include "headers/hardware/vga/vga_cga_mda.h" //CGA/MDA cursor support!

//Character is cursor position?
#define CHARISCURSOR (Sequencer_textmode_charindex==VGA->precalcs.cursorlocation)
//Scanline is cursor position?
#define SCANLINEISCURSOR1 (Rendery>=VGA->precalcs.CursorStartRegister_CursorScanLineStart)
#define SCANLINEISCURSOR2 (Rendery<=VGA->precalcs.CursorEndRegister_CursorScanLineEnd)
//Cursor is enabled atm?
#define CURSORENABLED1 (!VGA->precalcs.CursorStartRegister_CursorDisable)
#define CURSORENABLED2 (VGA->blink8)

OPTINLINE byte is_cursorscanline(VGA_Type *VGA,byte Rendery,word Sequencer_textmode_charindex) //Cursor scanline within character is cursor? Used to be: VGA_Type *VGA, byte ScanLine,uint_32 characterlocation
{
	byte cursorOK;
	if (CHARISCURSOR) //Character is cursor character?
	{
		if (CGAMDAEMULATION_ENABLED(VGA)) //CGA emulation has different cursors?
		{
			if (VGA->registers->specialCGAflags&8) //Split cursor?
			{
				cursorOK = (Rendery>=VGA->precalcs.CursorStartRegister_CursorScanLineStart); //Before?
				cursorOK |= (Rendery<=VGA->precalcs.CursorEndRegister_CursorScanLineEnd); //After?
			}
			else //Normal cursor?
			{
				cursorOK = (Rendery>=VGA->precalcs.CursorStartRegister_CursorScanLineStart); //Before?
				cursorOK &= (Rendery<=VGA->precalcs.CursorEndRegister_CursorScanLineEnd); //After?
			}
			switch (VGA->registers->CGARegisters[0xA]&0x60) //What cursor mode?
			{
				case 0x20: return 0; //Cursor Non-Display!
				case 0x00: return (VGA->blink8&&cursorOK); //Blink at normal rate(every 8 frames)?
				case 0x40: return (VGA->blink16&&cursorOK); //Blink, 1/16 Field Rate(every 16 frames)?
				case 0x60: return (VGA->blink32&&cursorOK); //Blink, 1/32 Field Rate(every 32 frames)?
			}
		}
		else //Normal VGA cursor?
		{
			cursorOK = CURSORENABLED1; //Cursor enabled?
			cursorOK &= CURSORENABLED2; //Cursor on?
			cursorOK &= SCANLINEISCURSOR1; //Scanline is within cursor top range?
			cursorOK &= SCANLINEISCURSOR2; //Scanline is within cursor bottom range?
		}
		return cursorOK; //Give if the cursor is OK!
	}
	return 0; //No cursor!
}

byte character=0;
word attribute=0; //Currently loaded data!
byte iscursor=0; //Are we a cursor scanline?
byte characterpixels[9]; //All possible character pixels!

extern LOADEDPLANESCONTAINER loadedplanes; //All read planes for the current processing!

byte charxbuffer[256]; //Full character inner x location!

void VGA_TextDecoder(VGA_Type *VGA, word loadedlocation)
{
	INLINEREGISTER byte x, attr3;
	INLINEREGISTER uint_32 charrow; //The row read!
	//We do nothing: text mode uses multiple planes at the same time!
	character = loadedplanes.splitplanes[0]; //Character!
	attribute = loadedplanes.splitplanes[1]<<VGA_SEQUENCER_ATTRIBUTESHIFT; //Attribute!
	iscursor = is_cursorscanline(VGA, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y, loadedlocation); //Are we a cursor?
	if (CGAMDAEMULATION_ENABLED(VGA)) //Enabled CGA/MDA emulation?
	{
		if (CGAEMULATION_ENABLED(VGA)) //Pure CGA mode?
		{
			//Read all 8 pixels with a possibility of 9 pixels to be safe!
			characterpixels[0] = getcharxy_CGA(character, 0, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[1] = getcharxy_CGA(character, 1, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[2] = getcharxy_CGA(character, 2, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[3] = getcharxy_CGA(character, 3, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[4] = getcharxy_CGA(character, 4, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[5] = getcharxy_CGA(character, 5, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[6] = getcharxy_CGA(character, 6, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[7] = getcharxy_CGA(character, 7, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[8] = 0; //Read all coordinates!
			//We're not displayed else, so don't care about output!
		}
		else if (MDAEMULATION_ENABLED(VGA)) //Pure MDA mode?
		{
			//Read all 9 pixels with a possibility of 9 pixels to be safe!
			characterpixels[0] = getcharxy_MDA(character, 0, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[1] = getcharxy_MDA(character, 1, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[2] = getcharxy_MDA(character, 2, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[3] = getcharxy_MDA(character, 3, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[4] = getcharxy_MDA(character, 4, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[5] = getcharxy_MDA(character, 5, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[6] = getcharxy_MDA(character, 6, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[7] = getcharxy_MDA(character, 7, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read all coordinates!
			characterpixels[8] = 0; //Read all coordinates!
		}
		else goto VGAtext;
	}
	else //VGA mode?
	{
	VGAtext: //VGA text catch-all!
		attr3 = (byte)attribute; //Load the attribute!
		attr3 >>= 3; //...
		attr3 &= 1; //... Take bit 3 to get the actual attribute we need!
		x = 0; //Start with the first pixel!
		charrow = getcharrow(VGA,attr3,character, (byte)((SEQ_DATA *)VGA->Sequencer)->charinner_y); //Read the current row to use!
		attr3 = 8; //How far to go?
		do //Process all coordinates of our row!
		{
			characterpixels[x] = (charrow&1); //Read current coordinate!
			charrow >>= 1; //Shift to the next pixel!
			++x; //Next pixel!
		} while (--attr3); //Loop while anything left!

		if (VGA->precalcs.characterwidth == 9) //What width? 9 wide?
		{
			if (VGA->registers->AttributeControllerRegisters.REGISTERS.ATTRIBUTEMODECONTROLREGISTER.LineGraphicsEnable || ((character & 0xE0) != 0xC0))
			{
				characterpixels[8] = 0; //9th bit is always background?
			}
			else //Duplicate of pixel 7?
			{
				characterpixels[8] = characterpixels[7]; //9th bit is a duplicate of 8th bit?
			}
		}
	}
	((SEQ_DATA *)VGA->Sequencer)->textx = &charxbuffer[0]; //Start taking our character pixels!
}

void VGA_Sequencer_TextMode(VGA_Type *VGA, SEQ_DATA *Sequencer, VGA_AttributeInfo *attributeinfo) //Render a text mode pixel!
{
	//First, full value to lookup!
	INLINEREGISTER word charinner;
	INLINEREGISTER byte pixel;
	if (Sequencer->textx==0) return; //Invalid pointer!
	charinner = *Sequencer->textx++; //Read the inner location of the row to read!
	charinner <<= 1;
	charinner |= 1; //Calculate our column value!
	attributeinfo->charinner_x = charinner = VGA->CRTC.charcolstatus[charinner]; //Load inner x!
	//Now retrieve the font/back pixel
	pixel = characterpixels[charinner]; //Load the current pixel!
	pixel |= iscursor; //Apply the cursor to the pixel!
	attributeinfo->fontpixel = pixel; //We're the font pixel?
	attributeinfo->attribute = attribute; //The attribute for this pixel!
}