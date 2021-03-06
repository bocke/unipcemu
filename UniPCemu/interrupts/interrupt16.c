/*

Copyright (C) 2019 - 2021 Superfury

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

#include "headers/types.h"
#include "headers/cpu/cpu.h"
#include "headers/cpu/interrupts.h" //BOOT loader!
#include "headers/cpu/easyregs.h" //Easy registers!
#include "headers/cpu/cb_manager.h" //Callback support!
#include "headers/cpu/protection.h" //Protection support!
#include "headers/header_dosbox.h" //Basic DOSBox compatibility.
#include "headers/cpu/easyregs.h" //Easy register support!
#include "headers/hardware/ports.h" //Port support!
#include "headers/cpu/biu.h" //BIU support!
//Keyboard interrupt!

void Dosbox_RealSetVec(byte interrupt, uint_32 realaddr)
{
	RealSetVec(interrupt,realaddr>>16,realaddr&0xFFFF); //Set the interrupt vector in real mode!
}

//#if SDL_VERSION_ATLEAST(1, 2, 14)
//We always can use lock since we don't depend on SDL for it, but generate input for processing ourselves!
#define CAN_USE_LOCK 1
//#endif

//static Bitu call_int16,call_irq1,call_irq6;

/* Nice table from BOCHS i should feel bad for ripping this */
#define none 0
struct {
  Bit16u normal;
  Bit16u shift;
  Bit16u control;
  Bit16u alt;
  } scan_to_scanascii[MAX_SCAN_CODE + 1] = {
      {   none,   none,   none,   none },
      { 0x011b, 0x011b, 0x011b, 0x01f0 }, /* escape */
      { 0x0231, 0x0221,   none, 0x7800 }, /* 1! */
      { 0x0332, 0x0340, 0x0300, 0x7900 }, /* 2@ */
      { 0x0433, 0x0423,   none, 0x7a00 }, /* 3# */
      { 0x0534, 0x0524,   none, 0x7b00 }, /* 4$ */
      { 0x0635, 0x0625,   none, 0x7c00 }, /* 5% */
      { 0x0736, 0x075e, 0x071e, 0x7d00 }, /* 6^ */
      { 0x0837, 0x0826,   none, 0x7e00 }, /* 7& */
      { 0x0938, 0x092a,   none, 0x7f00 }, /* 8* */
      { 0x0a39, 0x0a28,   none, 0x8000 }, /* 9( */
      { 0x0b30, 0x0b29,   none, 0x8100 }, /* 0) */
      { 0x0c2d, 0x0c5f, 0x0c1f, 0x8200 }, /* -_ */
      { 0x0d3d, 0x0d2b,   none, 0x8300 }, /* =+ */
      { 0x0e08, 0x0e08, 0x0e7f, 0x0ef0 }, /* backspace */
      { 0x0f09, 0x0f00, 0x9400,   none }, /* tab */
      { 0x1071, 0x1051, 0x1011, 0x1000 }, /* Q */
      { 0x1177, 0x1157, 0x1117, 0x1100 }, /* W */
      { 0x1265, 0x1245, 0x1205, 0x1200 }, /* E */
      { 0x1372, 0x1352, 0x1312, 0x1300 }, /* R */
      { 0x1474, 0x1454, 0x1414, 0x1400 }, /* T */
      { 0x1579, 0x1559, 0x1519, 0x1500 }, /* Y */
      { 0x1675, 0x1655, 0x1615, 0x1600 }, /* U */
      { 0x1769, 0x1749, 0x1709, 0x1700 }, /* I */
      { 0x186f, 0x184f, 0x180f, 0x1800 }, /* O */
      { 0x1970, 0x1950, 0x1910, 0x1900 }, /* P */
      { 0x1a5b, 0x1a7b, 0x1a1b, 0x1af0 }, /* [{ */
      { 0x1b5d, 0x1b7d, 0x1b1d, 0x1bf0 }, /* ]} */
      { 0x1c0d, 0x1c0d, 0x1c0a,   none }, /* Enter */
      {   none,   none,   none,   none }, /* L Ctrl */
      { 0x1e61, 0x1e41, 0x1e01, 0x1e00 }, /* A */
      { 0x1f73, 0x1f53, 0x1f13, 0x1f00 }, /* S */
      { 0x2064, 0x2044, 0x2004, 0x2000 }, /* D */
      { 0x2166, 0x2146, 0x2106, 0x2100 }, /* F */
      { 0x2267, 0x2247, 0x2207, 0x2200 }, /* G */
      { 0x2368, 0x2348, 0x2308, 0x2300 }, /* H */
      { 0x246a, 0x244a, 0x240a, 0x2400 }, /* J */
      { 0x256b, 0x254b, 0x250b, 0x2500 }, /* K */
      { 0x266c, 0x264c, 0x260c, 0x2600 }, /* L */
      { 0x273b, 0x273a,   none, 0x27f0 }, /* ;: */
      { 0x2827, 0x2822,   none, 0x28f0 }, /* '" */
      { 0x2960, 0x297e,   none, 0x29f0 }, /* `~ */
      {   none,   none,   none,   none }, /* L shift */
      { 0x2b5c, 0x2b7c, 0x2b1c, 0x2bf0 }, /* |\ */
      { 0x2c7a, 0x2c5a, 0x2c1a, 0x2c00 }, /* Z */
      { 0x2d78, 0x2d58, 0x2d18, 0x2d00 }, /* X */
      { 0x2e63, 0x2e43, 0x2e03, 0x2e00 }, /* C */
      { 0x2f76, 0x2f56, 0x2f16, 0x2f00 }, /* V */
      { 0x3062, 0x3042, 0x3002, 0x3000 }, /* B */
      { 0x316e, 0x314e, 0x310e, 0x3100 }, /* N */
      { 0x326d, 0x324d, 0x320d, 0x3200 }, /* M */
      { 0x332c, 0x333c,   none, 0x33f0 }, /* ,< */
      { 0x342e, 0x343e,   none, 0x34f0 }, /* .> */
      { 0x352f, 0x353f,   none, 0x35f0 }, /* /? */
      {   none,   none,   none,   none }, /* R Shift */
      { 0x372a, 0x372a, 0x9600, 0x37f0 }, /* * */
      {   none,   none,   none,   none }, /* L Alt */
      { 0x3920, 0x3920, 0x3920, 0x3920 }, /* space */
      {   none,   none,   none,   none }, /* caps lock */
      { 0x3b00, 0x5400, 0x5e00, 0x6800 }, /* F1 */
      { 0x3c00, 0x5500, 0x5f00, 0x6900 }, /* F2 */
      { 0x3d00, 0x5600, 0x6000, 0x6a00 }, /* F3 */
      { 0x3e00, 0x5700, 0x6100, 0x6b00 }, /* F4 */
      { 0x3f00, 0x5800, 0x6200, 0x6c00 }, /* F5 */
      { 0x4000, 0x5900, 0x6300, 0x6d00 }, /* F6 */
      { 0x4100, 0x5a00, 0x6400, 0x6e00 }, /* F7 */
      { 0x4200, 0x5b00, 0x6500, 0x6f00 }, /* F8 */
      { 0x4300, 0x5c00, 0x6600, 0x7000 }, /* F9 */
      { 0x4400, 0x5d00, 0x6700, 0x7100 }, /* F10 */
      {   none,   none,   none,   none }, /* Num Lock */
      {   none,   none,   none,   none }, /* Scroll Lock */
      { 0x4700, 0x4737, 0x7700, 0x0007 }, /* 7 Home */
      { 0x4800, 0x4838, 0x8d00, 0x0008 }, /* 8 UP */
      { 0x4900, 0x4939, 0x8400, 0x0009 }, /* 9 PgUp */
      { 0x4a2d, 0x4a2d, 0x8e00, 0x4af0 }, /* - */
      { 0x4b00, 0x4b34, 0x7300, 0x0004 }, /* 4 Left */
      { 0x4cf0, 0x4c35, 0x8f00, 0x0005 }, /* 5 */
      { 0x4d00, 0x4d36, 0x7400, 0x0006 }, /* 6 Right */
      { 0x4e2b, 0x4e2b, 0x9000, 0x4ef0 }, /* + */
      { 0x4f00, 0x4f31, 0x7500, 0x0001 }, /* 1 End */
      { 0x5000, 0x5032, 0x9100, 0x0002 }, /* 2 Down */
      { 0x5100, 0x5133, 0x7600, 0x0003 }, /* 3 PgDn */
      { 0x5200, 0x5230, 0x9200, 0x0000 }, /* 0 Ins */
      { 0x5300, 0x532e, 0x9300,   none }, /* Del */
      {   none,   none,   none,   none },
      {   none,   none,   none,   none },
      { 0x565c, 0x567c,   none,   none }, /* (102-key) */
      { 0x8500, 0x8700, 0x8900, 0x8b00 }, /* F11 */
      { 0x8600, 0x8800, 0x8a00, 0x8c00 }  /* F12 */
      };

OPTINLINE bool BIOS_AddKeyToBuffer(Bit16u code) {
	Bit16u start,end,head,tail,ttail;
	if (mem_readb(BIOS_KEYBOARD_FLAGS2)&8) return true;
	start=mem_readw(BIOS_KEYBOARD_BUFFER_START);
	end	 =mem_readw(BIOS_KEYBOARD_BUFFER_END);
	head =mem_readw(BIOS_KEYBOARD_BUFFER_HEAD);
	tail =mem_readw(BIOS_KEYBOARD_BUFFER_TAIL);
	ttail=tail+2;
	if (ttail>=end) {
		ttail=start;
	}
	/* Check for buffer Full */
	if (ttail==head) return false;
	real_writew(0x40,tail,code);
	mem_writew(BIOS_KEYBOARD_BUFFER_TAIL,ttail);
	return true;
}

OPTINLINE void add_key(Bit16u code) {
	if (code!=0) BIOS_AddKeyToBuffer(code);
}

OPTINLINE bool get_key(Bit16u *code) {
	Bit16u start,end,head,tail,thead;
	start=mem_readw(BIOS_KEYBOARD_BUFFER_START);
	end	 =mem_readw(BIOS_KEYBOARD_BUFFER_END);
	head =mem_readw(BIOS_KEYBOARD_BUFFER_HEAD);
	tail =mem_readw(BIOS_KEYBOARD_BUFFER_TAIL);

	if (head==tail) return false;
	thead=head+2;
	if (thead>=end) thead=start;
	mem_writew(BIOS_KEYBOARD_BUFFER_HEAD,thead);
	*code = real_readw(0x40,head);
	return true;
}

OPTINLINE bool check_key(Bit16u *code) {
	Bit16u head,tail;
	head =mem_readw(BIOS_KEYBOARD_BUFFER_HEAD);
	tail =mem_readw(BIOS_KEYBOARD_BUFFER_TAIL);
	if (head==tail) return false;
	*code = real_readw(0x40,head);
	return true;
}

	/*	Flag Byte 1 
		bit 7 =1 INSert active
		bit 6 =1 Caps Lock active
		bit 5 =1 Num Lock active
		bit 4 =1 Scroll Lock active
		bit 3 =1 either Alt pressed
		bit 2 =1 either Ctrl pressed
		bit 1 =1 Left Shift pressed
		bit 0 =1 Right Shift pressed
	*/
	/*	Flag Byte 2
		bit 7 =1 INSert pressed
		bit 6 =1 Caps Lock pressed
		bit 5 =1 Num Lock pressed
		bit 4 =1 Scroll Lock pressed
		bit 3 =1 Pause state active
		bit 2 =1 Sys Req pressed
		bit 1 =1 Left Alt pressed
		bit 0 =1 Left Ctrl pressed
	*/
	/* 
		Keyboard status byte 3
		bit 7 =1 read-ID in progress
		bit 6 =1 last code read was first of two ID codes
		bit 5 =1 force Num Lock if read-ID and enhanced keyboard
		bit 4 =1 enhanced keyboard installed
		bit 3 =1 Right Alt pressed
		bit 2 =1 Right Ctrl pressed
		bit 1 =1 last code read was E0h
		bit 0 =1 last code read was E1h
	*/


/* the scancode is in reg_al */
void IRQ1_Handler() {
/* handling of the locks key is difficult as sdl only gives
 * states for numlock capslock. 
 */
	Bitu scancode=REG_AL;	/* Read the code */
	Bit16u asciiscan;

	Bit8u flags1,flags2,flags3,leds;
	Bit16u token;

	flags1=mem_readb(BIOS_KEYBOARD_FLAGS1);
	flags2=mem_readb(BIOS_KEYBOARD_FLAGS2);
	flags3=mem_readb(BIOS_KEYBOARD_FLAGS3);
	leds  =mem_readb(BIOS_KEYBOARD_LEDS); 
#ifdef CAN_USE_LOCK
	/* No hack anymore! */
#else
	flags2&=~(0x40+0x20);//remove numlock/capslock pressed (hack for sdl only reporting states)
#endif
	switch (scancode) {
	/* First the hard ones  */
	case 0xfa:	/* ack. Do nothing for now */
		break;
	case 0xe1:	/* Extended key special. Only pause uses this */
		flags3 |=0x01;
		break;
	case 0xe0:						/* Extended key */
		flags3 |=0x02;
		break;
	case 0x1d:						/* Ctrl Pressed */
		if (!(flags3 &0x01)) {
			flags1 |=0x04;
			if (flags3 &0x02) flags3 |=0x04;
			else flags2 |=0x01;
		}	/* else it's part of the pause scancodes */
		break;
	case 0x9d:						/* Ctrl Released */
		if (!(flags3 &0x01)) {
			if (flags3 &0x02) flags3 &=~0x04;
			else flags2 &=~0x01;
			if( !( (flags3 &0x04) || (flags2 &0x01) ) ) flags1 &=~0x04;
		}
		break;
	case 0x2a:						/* Left Shift Pressed */
		flags1 |=0x02;
		break;
	case 0xaa:						/* Left Shift Released */
		flags1 &=~0x02;
		break;
	case 0x36:						/* Right Shift Pressed */
		flags1 |=0x01;
		break;
	case 0xb6:						/* Right Shift Released */
		flags1 &=~0x01;
		break;
	case 0x38:						/* Alt Pressed */
		flags1 |=0x08;
		if (flags3 &0x02) flags3 |=0x08;
		else flags2 |=0x02;
		break;
	case 0xb8:						/* Alt Released */
		if (flags3 &0x02) flags3 &= ~0x08;
		else flags2 &= ~0x02;
		if( !( (flags3 &0x08) || (flags2 &0x02) ) ) { /* Both alt released */
			flags1 &= ~0x08;
			token =mem_readb(BIOS_KEYBOARD_TOKEN);
			if(token != 0){
				add_key(token);
				mem_writeb(BIOS_KEYBOARD_TOKEN,0);
			}
		}
		break;

#ifdef CAN_USE_LOCK
	case 0x3a:flags2 |=0x40;break;//CAPSLOCK
	case 0xba:flags1 ^=0x40;flags2 &=~0x40;leds ^=0x04;break;
#else
	case 0x3a:flags2 |=0x40;flags1 |=0x40;leds |=0x04;break; //SDL gives only the state instead of the toggle					/* Caps Lock */
	case 0xba:flags1 &=~0x40;leds &=~0x04;break;
#endif
	case 0x45:
		if (flags3 &0x01) {
			/* last scancode of pause received; first remove 0xe1-prefix */
			flags3 &=~0x01;
			mem_writeb(BIOS_KEYBOARD_FLAGS3,flags3);
			if (flags2&1) {
				/* ctrl-pause (break), special handling needed:
				   add zero to the keyboard buffer, call int 0x1b which
				   sets ctrl-c flag which calls int 0x23 in certain dos
				   input/output functions;    not handled */
			} else if ((flags2&8)==0) {
				/* normal pause key, enter loop */
				mem_writeb(BIOS_KEYBOARD_FLAGS2,flags2|8);
				IO_Write(0x20,0x20);
				while (mem_readb(BIOS_KEYBOARD_FLAGS2)&8) CALLBACK_Idle();	// pause loop
				REG_IP+=5;	// skip out 20,20
				CPU_flushPIQ(-1); //Flush the PIQ!
				return;
			}
		} else {
			/* Num Lock */
#ifdef CAN_USE_LOCK
			flags2 |=0x20;
#else
			flags2 |=0x20;
			flags1 |=0x20;
			leds |=0x02;
#endif
		}
		break;
	case 0xc5:
		if (flags3 &0x01) {
			/* pause released */
			flags3 &=~0x01;
		} else {
#ifdef CAN_USE_LOCK
			flags1^=0x20;
			leds^=0x02;
			flags2&=~0x20;
#else
			/* Num Lock released */
			flags1 &=~0x20;
			leds &=~0x02;
#endif
		}
		break;
	case 0x46:flags2 |=0x10;break;				/* Scroll Lock SDL Seems to do this one fine (so break and make codes) */
	case 0xc6:flags1 ^=0x10;flags2 &=~0x10;leds ^=0x01;break;
//	case 0x52:flags2|=128;break;//See numpad					/* Insert */
	case 0xd2:	
		if(flags3&0x02) { /* Maybe honour the insert on keypad as well */
			flags1^=0x80;
			flags2&=~0x80;
			break; 
		} else {
			goto irq1_end;/*Normal release*/ 
		}
	case 0x47:		/* Numpad */
	case 0x48:
	case 0x49:
	case 0x4b:
	case 0x4c:
	case 0x4d:
	case 0x4f:
	case 0x50:
	case 0x51:
	case 0x52:
	case 0x53: /* del . Not entirely correct, but works fine */
		if(flags3 &0x02) {	/*extend key. e.g key above arrows or arrows*/
			if(scancode == 0x52) flags2 |=0x80; /* press insert */		   
			if(flags1 &0x08) {
				add_key(scan_to_scanascii[scancode].normal+0x5000);
			} else if (flags1 &0x04) {
				add_key((scan_to_scanascii[scancode].control&0xff00)|0xe0);
			} else if( ((flags1 &0x3) != 0) || ((flags1 &0x20) != 0) ) {
				add_key((scan_to_scanascii[scancode].shift&0xff00)|0xe0);
			} else add_key((scan_to_scanascii[scancode].normal&0xff00)|0xe0);
			break;
		}
		if(flags1 &0x08) {
			token = mem_readb(BIOS_KEYBOARD_TOKEN);
			token = token*10 + (Bit8u)(scan_to_scanascii[scancode].alt&0xff);
			mem_writeb(BIOS_KEYBOARD_TOKEN,(byte)token);
		} else if (flags1 &0x04) {
			add_key(scan_to_scanascii[scancode].control);
		} else if( ((flags1 &0x3) != 0) || ((flags1 &0x20) != 0) ) {
			add_key(scan_to_scanascii[scancode].shift);
		} else add_key(scan_to_scanascii[scancode].normal);
		break;

	default: /* Normal Key */
		/* Now Handle the releasing of keys and see if they match up for a code */
		/* Handle the actual scancode */
		if (scancode & 0x80) goto irq1_end;
		if (scancode > MAX_SCAN_CODE) goto irq1_end;
		if (flags1 & 0x08) { 					/* Alt is being pressed */
			asciiscan=scan_to_scanascii[scancode].alt;
#if 0 /* old unicode support disabled*/
		} else if (ascii) {
			asciiscan=(scancode << 8) | ascii;
#endif
		} else if (flags1 & 0x04) {					/* Ctrl is being pressed */
			asciiscan=scan_to_scanascii[scancode].control;
		} else if (flags1 & 0x03) {					/* Either shift is being pressed */
			asciiscan=scan_to_scanascii[scancode].shift;
		} else {
			asciiscan=scan_to_scanascii[scancode].normal;
		}
		/* cancel shift is letter and capslock active */
		if(flags1&64) {
			if(flags1&3) {
				/*cancel shift */  
				if(((asciiscan&0x00ff) >0x40) && ((asciiscan&0x00ff) <0x5b)) 
					asciiscan=scan_to_scanascii[scancode].normal; 
			} else {
				/* add shift */
	   			if(((asciiscan&0x00ff) >0x60) && ((asciiscan&0x00ff) <0x7b)) 
					asciiscan=scan_to_scanascii[scancode].shift; 
			}
		}
		if (flags3 &0x02) {
			/* extended key (numblock), return and slash need special handling */
			if (scancode==0x1c) {	/* return */
				if (flags1 &0x08) asciiscan=0xa600;
				else asciiscan=(asciiscan&0xff)|0xe000;
			} else if (scancode==0x35) {	/* slash */
				if (flags1 &0x08) asciiscan=0xa400;
				else if (flags1 &0x04) asciiscan=0x9500;
				else asciiscan=0xe02f;
			}
		}
		add_key(asciiscan);
		break;
	};
irq1_end:
	if(scancode !=0xe0) flags3 &=~0x02;									//Reset 0xE0 Flag
	mem_writeb(BIOS_KEYBOARD_FLAGS1,flags1);
	if ((scancode&0x80)==0) flags2&=0xf7;
	mem_writeb(BIOS_KEYBOARD_FLAGS2,flags2);
	mem_writeb(BIOS_KEYBOARD_FLAGS3,flags3);
	mem_writeb(BIOS_KEYBOARD_LEDS,leds);
/*	IO_Write(0x20,0x20); moved out of handler to be virtualizable */
#if 0
/* Signal the keyboard for next code */
/* In dosbox port 60 reads do this as well */
	Bit8u old61=IO_Read(0x61);
	IO_Write(0x61,old61 | 128);
	IO_Write(0x64,0xae);
#endif
	return;
}


/* check whether key combination is enhanced or not,
   translate key if necessary */
OPTINLINE bool IsEnhancedKey(Bit16u *key) {
	/* test for special keys (return and slash on numblock) */
	if ((*key>>8)==0xe0) {
		if (((*key&0xff)==0x0a) || ((*key&0xff)==0x0d)) {
			/* key is return on the numblock */
			*key=(*key&0xff)|0x1c00;
		} else {
			/* key is slash on the numblock */
			*key=(*key&0xff)|0x3500;
		}
		/* both keys are not considered enhanced keys */
		return false;
	} else if (((*key>>8)>0x84) || (((*key&0xff)==0xf0) && (*key>>8))) {
		/* key is enhanced key (either scancode part>0x84 or
		   specially-marked keyboard combination, low part==0xf0) */
		return true;
	}
	/* convert key if necessary (extended keys) */
	if ((*key>>8) && ((*key&0xff)==0xe0))  {
		*key&=0xff00;
	}
	return false;
}

void INT16_Handler() {
	Bit16u temp=0;
	switch (REG_AH) {
	case 0x00: /* GET KEYSTROKE */
		if ((get_key(&temp)) && (!IsEnhancedKey(&temp))) {
			/* normal key found, return translated key in ax */
			REG_AX=temp;
		} else {
			/* enter small idle loop to allow for irqs to happen */
			REG_IP+=1;
			CPU_flushPIQ(-1); //Flush the PIQ!
		}
		break;
	case 0x10: /* GET KEYSTROKE (enhanced keyboards only) */
		if (get_key(&temp)) {
			if (((temp&0xff)==0xf0) && (temp>>8)) {
				/* special enhanced key, clear low part before returning key */
				temp&=0xff00;
			}
			REG_AX=temp;
		} else {
			/* enter small idle loop to allow for irqs to happen */
			REG_IP+=1;
			CPU_flushPIQ(-1); //Flush the PIQ!
		}
		break;
	case 0x01: /* CHECK FOR KEYSTROKE */
		// enable interrupt-flag after IRET of this int16
		CALLBACK_SIF(1); //Set the resultant Interrupt Flag to 1!
		for (;;) {
			if (check_key(&temp)) {
				if (!IsEnhancedKey(&temp)) {
					/* normal key, return translated key in ax */
					CALLBACK_SZF(false);
					REG_AX=temp;
					break;
				} else {
					/* remove enhanced key from buffer and ignore it */
					get_key(&temp);
				}
			} else {
				/* no key available */
				CALLBACK_SZF(true);
				break;
			}
//			CALLBACK_Idle();
		}
		break;
	case 0x11: /* CHECK FOR KEYSTROKE (enhanced keyboards only) */
		if (!check_key(&temp)) {
			CALLBACK_SZF(true);
		} else {
			CALLBACK_SZF(false);
			if (((temp&0xff)==0xf0) && (temp>>8)) {
				/* special enhanced key, clear low part before returning key */
				temp&=0xff00;
			}
			REG_AX=temp;
		}
		break;
	case 0x02:	/* GET SHIFT FlAGS */
		REG_AL=mem_readb(BIOS_KEYBOARD_FLAGS1);
		break;
	case 0x03:	/* SET TYPEMATIC RATE AND DELAY */
		if (REG_AL == 0x00) { // set default delay and rate
			IO_Write(0x60,0xf3);
			IO_Write(0x60,0x20); // 500 msec delay, 30 cps
		} else if (REG_AL == 0x05) { // set repeat rate and delay
			IO_Write(0x60,0xf3);
			IO_Write(0x60,(REG_BH&3)<<5|(REG_BL&0x1f));
		} /*else {
			LOG(LOG_BIOS,LOG_ERROR)("INT16:Unhandled Typematic Rate Call %2X REG_BX=%X",reg_al,reg_bx);
		}*/
		break;
	case 0x05:	/* STORE KEYSTROKE IN KEYBOARD BUFFER */
		if (BIOS_AddKeyToBuffer(REG_CX)) REG_AL=0;
		else REG_AL=1;
		break;
	case 0x12: /* GET EXTENDED SHIFT STATES */
		REG_AL=mem_readb(BIOS_KEYBOARD_FLAGS1);
		REG_AH=mem_readb(BIOS_KEYBOARD_FLAGS2);		
		break;
	case 0x55:
		/* Weird call used by some dos apps */
		break;
	default:
		break;

	};
}

//Keyboard initialisation. src/gui/sdlmain.cpp
extern bool startup_state_numlock;
extern bool startup_state_capslock;

void InitBiosSegment() {
	Bit8u flag1;
	Bit8u leds;
	/* Setup the variables for keyboard in the bios data segment */
	mem_writew(BIOS_KEYBOARD_BUFFER_START,0x1e);
	mem_writew(BIOS_KEYBOARD_BUFFER_END,0x3e);
	mem_writew(BIOS_KEYBOARD_BUFFER_HEAD,0x1e);
	mem_writew(BIOS_KEYBOARD_BUFFER_TAIL,0x1e);
	flag1 = 0;
	leds = 16; /* Ack recieved */
//MAPPER_Init takes care of this now ?
//	if(startup_state_capslock) { flag1|=0x40; leds|=0x04;}
//	if(startup_state_numlock){ flag1|=0x20; leds|=0x02;}
	mem_writeb(BIOS_KEYBOARD_FLAGS1,flag1);
	mem_writeb(BIOS_KEYBOARD_FLAGS2,0);
	mem_writeb(BIOS_KEYBOARD_FLAGS3,16); /* Enhanced keyboard installed */	
	mem_writeb(BIOS_KEYBOARD_TOKEN,0);
	mem_writeb(BIOS_KEYBOARD_LEDS,leds);
}

void BIOS_SetupKeyboard() {
	byte irq1handler = 0;
	/* Init the variables */
	InitBiosSegment();

	/* Allocate/setup a callback for int 0x16 and for standard IRQ 1 handler */
	addCBHandler(CB_DOSBOX_INT16,&INT16_Handler,0x16); //Register our handler our way!

	addCBHandler(CB_DOSBOX_IRQ1,&IRQ1_Handler,(uint_32)BIOS_DEFAULT_IRQ1_LOCATION);
	Dosbox_RealSetVec(0x09,(uint_32)BIOS_DEFAULT_IRQ1_LOCATION); //Our pointer!

	irq1handler = PORT_IN_B(0x21); //Read the current IRQ status!
	irq1handler &= ~0x02; //Enable IRQ1: Keyboard handler!
	PORT_OUT_B(0x21,irq1handler); //Enable our IRQ!

	// pseudocode for CB_IRQ1:
	//	push ax
	//	in al, 0x60
	//	mov ah, 0x4f
	//	stc
	//	int 15
	//	jc skip
	//	callback IRQ1_Handler
	//	label skip:
	//	cli
	//	mov al, 0x20
	//	out 0x20, al
	//	pop ax
	//	iret
}

void BIOS_int16()
{
	//Passthrough to dosbox handler!
	INT16_Handler(); //Execute int16 handler of DOSBox!
}