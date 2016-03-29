#define VGA_CRTCONTROLLER

#include "headers/hardware/vga/vga.h"
#include "headers/hardware/vga/vga_precalcs.h" //Precalculation typedefs etc.
#include "headers/hardware/vga/vga_sequencer_textmode.h" //VGA Attribute controller!
#include "headers/hardware/vga/vga_crtcontroller.h"

//Horizontal information!

OPTINLINE word getHorizontalDisplayStart(VGA_Type *VGA) //How many pixels to take off the active display x to get the start x!
{
	return VGA->precalcs.horizontaldisplaystart; //Horizontal start
}

OPTINLINE word getHorizontalDisplayEnd(VGA_Type *VGA) //What is the last character start x of the current line? (max character-1)
{
	return VGA->precalcs.horizontaldisplayend; //Horizontal End of display area!
}

OPTINLINE word getHorizontalBlankingStart(VGA_Type *VGA)
{
	return VGA->precalcs.horizontalblankingstart; //When to start blanking horizontally!
}

OPTINLINE word getHorizontalBlankingEnd(VGA_Type *VGA)
{
	return VGA->precalcs.horizontalblankingend; //When to stop blanking horizontally after starting!
}

OPTINLINE word getHorizontalRetraceStart(VGA_Type *VGA) //When to start retracing (vblank)
{
	return VGA->precalcs.horizontalretracestart; //When to start vertical retrace!
}

OPTINLINE word getHorizontalRetraceEnd(VGA_Type *VGA)
{
	return VGA->precalcs.horizontalretraceend; //When to stop vertical retrace.
}

OPTINLINE word getHorizontalTotal(VGA_Type *VGA)
{
	return VGA->precalcs.horizontaltotal; //Horizontal total (full resolution plus horizontal retrace)!
}

//Vertical information

OPTINLINE word getVerticalDisplayEnd(VGA_Type *VGA)
{
	return VGA->precalcs.verticaldisplayend; //Vertical Display End Register value!
}

OPTINLINE word getVerticalBlankingStart(VGA_Type *VGA)
{
	return VGA->precalcs.verticalblankingstart; //Vertical Blanking Start value!
}

OPTINLINE word getVerticalBlankingEnd(VGA_Type *VGA)
{
	return VGA->precalcs.verticalblankingend; //Vertical Blanking End value!
}

OPTINLINE word getVerticalRetraceStart(VGA_Type *VGA) //When to start retracing (vblank)
{
	return VGA->precalcs.verticalretracestart; //When to start vertical retrace!
}

OPTINLINE word getVerticalRetraceEnd(VGA_Type *VGA)
{
	return VGA->precalcs.verticalretraceend; //When to stop vertical retrace.
}

OPTINLINE word getVerticalTotal(VGA_Type *VGA)
{
	return VGA->precalcs.verticaltotal; //Full resolution plus vertical retrace!
}

//Full screen resolution = HTotal x VTotal.

word get_display_y(VGA_Type *VGA, word scanline) //Vertical check!
{
	if (((VGA->registers->specialCGAflags&0x81)==1) || ((VGA->registers->specialMDAflags&0x81)==1)) return get_display_CGA_y(VGA,scanline); //Give CGA timing!
	word signal;
	signal = VGA_OVERSCAN; //Init to overscan!
	if (scanline>=getVerticalTotal(VGA)) //VTotal?
	{
		signal |= VGA_SIGNAL_VTOTAL; //VTotal notify!
	}
	
	if (scanline==getVerticalRetraceStart(VGA)) //Retracing to line 0?
	{
		signal |= VGA_SIGNAL_VRETRACESTART; //Vertical retracing: do nothing!
	}
	
	if ((scanline&0xF)==getVerticalRetraceEnd(VGA))
	{
		signal |= VGA_SIGNAL_VRETRACEEND;
	}
	
	if (scanline==getVerticalBlankingStart(VGA))
	{
		signal |= VGA_SIGNAL_VBLANKSTART; //Start blanking!
	}
	
	if ((scanline&0x7F)==getVerticalBlankingEnd(VGA)) //Probably 7 bits used wide? Maybe 8?
	{
		signal |= VGA_SIGNAL_VBLANKEND; //End blanking!
	}

	//We're overscan or display!
	if (scanline<getVerticalDisplayEnd(VGA)) //Vertical overscan?
	{
		signal |= VGA_VACTIVEDISPLAY; //Vertical active display!
	}
	
	return signal; //What signal!
}

word get_display_x(VGA_Type *VGA, word x) //Horizontal check!
{
	if (((VGA->registers->specialCGAflags&0x81)==1) || ((VGA->registers->specialMDAflags&0x81)==1)) return get_display_CGA_x(VGA,x); //Give CGA timing!
	word signal;
	signal = VGA_OVERSCAN; //Init to overscan!
	word hchar = VGA->CRTC.charcolstatus[x<<1]; //What character?
	if (x>=getHorizontalTotal(VGA)) //HTotal?
	{
		signal |= VGA_SIGNAL_HTOTAL; //HTotal notify!
	}
	//First, check vertical/horizontal retrace, blanking, overline!
	if (x==getHorizontalRetraceStart(VGA)) //Might be retracing to pixel 0?
	{
		signal |= VGA_SIGNAL_HRETRACESTART; //Retracing: do nothing!
	}
	
	if ((hchar&0x1F)==getHorizontalRetraceEnd(VGA)) //End of horizontal retrace?
	{
		signal |= VGA_SIGNAL_HRETRACEEND; //End of horizontal retrace!
	}
	
	//Not special: we're processing display! Priority: blanking, display, overscan!
	
	if (x==getHorizontalBlankingStart(VGA)) //Horizontal blanking start?
	{
		signal |= VGA_SIGNAL_HBLANKSTART; //Blanking!
	}
	
	if ((hchar&0x3F)==getHorizontalBlankingEnd(VGA)) //We end blanking AFTER this character!
	{
		signal |= VGA_SIGNAL_HBLANKEND; //End blanking!
	}
	
	//We're overscan or display!
	if ((x>=getHorizontalDisplayStart(VGA)) && (x<getHorizontalDisplayEnd(VGA))) //Display area?
	{
		signal |= VGA_HACTIVEDISPLAY; //Horizontal active display!
	}
	
	return signal; //What signal!
}