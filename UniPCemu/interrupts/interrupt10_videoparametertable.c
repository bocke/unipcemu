#include "headers/types.h" //Basic types!
#include "headers/interrupts/interrupt10.h" //Video interrupt support!
#include "headers/cpu/mmu.h" //Memory support!

//Our ROMs to write our data to!
extern byte EMU_BIOS[0x10000];
extern byte EMU_VGAROM[0x10000];

const byte vparams[] = {
	// 40x25 mode 0 and 1 crtc registers
	0x38, 0x28, 0x2d, 0x0a, 0x1f, 0x06, 0x19, 0x1c, 0x02, 0x07, 0x06, 0x07, 0,0,0,0,
	// 80x25 mode 2 and 3 crtc registers
	0x71, 0x50, 0x5a, 0x0a, 0x1f, 0x06, 0x19, 0x1c, 0x02, 0x07, 0x06, 0x07, 0,0,0,0,
	// graphics modes 4, 5 and 6
	0x38, 0x28, 0x2d, 0x0a, 0x7f, 0x06, 0x64, 0x70, 0x02, 0x01, 0x06, 0x07, 0,0,0,0,
	// mode 7 MDA text
	0x61, 0x50, 0x52, 0x0f, 0x19, 0x06, 0x19, 0x19, 0x02, 0x0d, 0x0b, 0x0c, 0,0,0,0,
	// buffer length words 2048, 4096, 16384, 16384
	0x00, 0x08, 0x00, 0x10, 0x00, 0x40, 0x00, 0x40,
	// columns
	40, 40, 80, 80, 40, 40, 80, 80,
	// CGA mode register
	0x2c, 0x28, 0x2d, 0x29, 0x2a, 0x2e, 0x1e, 0x29
};

static byte video_parameter_table_vga[0x40*0x1d]={
// video parameter table for mode 0 (cga emulation)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 1 (cga emulation)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 2 (cga emulation)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 3 (cga emulation)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 4
  0x28, 0x18, 0x08, 0x00, 0x40, // bios data
  0x09, 0x00, 0x00, 0x02, // sequencer registers
  0x63, // misc output registers
  0x2d, 0x27, 0x28, 0x90, 0x2b, 0x80, 0xbf, 0x1f,       // crtc registers 0-7
  0x00, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x9c, 0x8e, 0x8f, 0x14, 0x00, 0x96, 0xb9, 0xa2, 0xff, // crtc registers 16-24
  0x00, 0x13, 0x15, 0x17, 0x02, 0x04, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x01, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0f, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 5
  0x28, 0x18, 0x08, 0x00, 0x40, // bios data
  0x09, 0x00, 0x00, 0x02, // sequencer registers
  0x63, // misc output registers
  0x2d, 0x27, 0x28, 0x90, 0x2b, 0x80, 0xbf, 0x1f,       // crtc registers 0-7
  0x00, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x9c, 0x8e, 0x8f, 0x14, 0x00, 0x96, 0xb9, 0xa2, 0xff, // crtc registers 16-24
  0x00, 0x13, 0x15, 0x17, 0x02, 0x04, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x01, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0f, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 6
  0x50, 0x18, 0x08, 0x00, 0x40, // bios data
  0x09, 0x0f, 0x00, 0x02, // sequencer registers
  0x63, // misc output registers
  0x5f, 0x4f, 0x50, 0x82, 0x54, 0x80, 0xbf, 0x1f,       // crtc registers 0-7
  0x00, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x9c, 0x8e, 0x8f, 0x28, 0x00, 0x96, 0xb9, 0xc2, 0xff, // crtc registers 16-24
  0x00, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,       // attr registers 0-7
  0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,       // attr registers 8-15
  0x01, 0x00, 0x01, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 7
  0x50, 0x18, 0x10, 0x00, 0x10, // bios data
  0x00, 0x0f, 0x00, 0x07, // sequencer registers
  0x66, // misc output registers
  0x5f, 0x4f, 0x50, 0x82, 0x55, 0x81, 0xbf, 0x1f,       // crtc registers 0-7
  0x00, 0x4f, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x9c, 0x8e, 0x8f, 0x28, 0x0f, 0x96, 0xb9, 0xa3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,       // attr registers 0-7
  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,       // attr registers 8-15
  0x0c, 0x00, 0x0f, 0x08, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0a, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 8
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 9
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode a
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode b
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode c
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode d
  0x28, 0x18, 0x08, 0x00, 0x20, // bios data
  0x09, 0x0f, 0x00, 0x02, // sequencer registers
  0x63, // misc output registers
  0x2d, 0x27, 0x28, 0x90, 0x2b, 0x80, 0xbf, 0x1f,       // crtc registers 0-7
  0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x9c, 0x8e, 0x8f, 0x14, 0x00, 0x96, 0xb9, 0xe3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x01, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode e
  0x50, 0x18, 0x08, 0x00, 0x40, // bios data
  0x01, 0x0f, 0x00, 0x02, // sequencer registers
  0x63, // misc output registers
  0x5f, 0x4f, 0x50, 0x82, 0x54, 0x80, 0xbf, 0x1f,       // crtc registers 0-7
  0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x9c, 0x8e, 0x8f, 0x28, 0x00, 0x96, 0xb9, 0xe3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x01, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode f (64k graphics memory)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 10 (64k graphics memory)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode f (>64k graphics memory)
  0x50, 0x18, 0x0e, 0x00, 0x80, // bios data
  0x01, 0x0f, 0x00, 0x02, // sequencer registers
  0xa2, // misc output registers
  0x5f, 0x4f, 0x50, 0x82, 0x54, 0x80, 0xbf, 0x1f,       // crtc registers 0-7
  0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x83, 0x85, 0x5d, 0x28, 0x0f, 0x63, 0xba, 0xe3, 0xff, // crtc registers 16-24
  0x00, 0x08, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00,       // attr registers 0-7
  0x00, 0x08, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00,       // attr registers 8-15
  0x0b, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 10 (>64k graphics memory)
  0x50, 0x18, 0x0e, 0x00, 0x80, // bios data
  0x01, 0x0f, 0x00, 0x02, // sequencer registers
  0xa3, // misc output registers
  0x5f, 0x4f, 0x50, 0x82, 0x54, 0x80, 0xbf, 0x1f,       // crtc registers 0-7
  0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x83, 0x85, 0x5d, 0x28, 0x0f, 0x63, 0xba, 0xe3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,       // attr registers 0-7
  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,       // attr registers 8-15
  0x01, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 0 (350 lines)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 1 (350 lines)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 2 (350 lines)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 3 (350 lines)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode e
  0x28, 0x18, 0x10, 0x00, 0x08, // bios data
  0x08, 0x0f, 0x00, 0x07, // sequencer registers
  0x67, // misc output registers
  0x2d, 0x27, 0x28, 0x90, 0x2b, 0xa0, 0xbf, 0x1f,       // crtc registers 0-7
  0x00, 0x4f, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x9c, 0x8e, 0x8f, 0x14, 0x1f, 0x96, 0xb9, 0xa3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,       // attr registers 0-7
  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,       // attr registers 8-15
  0x0c, 0x00, 0x0f, 0x08, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode f
  0x50, 0x18, 0x10, 0x00, 0x10, // bios data
  0x00, 0x0f, 0x00, 0x07, // sequencer registers
  0x67, // misc output registers
  0x5f, 0x4f, 0x50, 0x82, 0x55, 0x81, 0xbf, 0x1f,       // crtc registers 0-7
  0x00, 0x4f, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x9c, 0x8e, 0x8f, 0x28, 0x1f, 0x96, 0xb9, 0xa3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,       // attr registers 0-7
  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,       // attr registers 8-15
  0x0c, 0x00, 0x0f, 0x08, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 10
  0x50, 0x18, 0x10, 0x00, 0x10, // bios data
  0x00, 0x0f, 0x00, 0x07, // sequencer registers
  0x66, // misc output registers
  0x5f, 0x4f, 0x50, 0x82, 0x55, 0x81, 0xbf, 0x1f,       // crtc registers 0-7
  0x00, 0x4f, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x9c, 0x8e, 0x8f, 0x28, 0x0f, 0x96, 0xb9, 0xa3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,       // attr registers 0-7
  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,       // attr registers 8-15
  0x0c, 0x00, 0x0f, 0x08, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0a, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 11
  0x50, 0x1d, 0x10, 0x00, 0xa0, // bios data
  0x01, 0x0f, 0x00, 0x02, // sequencer registers
  0xe3, // misc output registers
  0x5f, 0x4f, 0x50, 0x82, 0x54, 0x80, 0x0b, 0x3e,       // crtc registers 0-7
  0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0xea, 0x8c, 0xdf, 0x28, 0x00, 0xe7, 0x04, 0xc3, 0xff, // crtc registers 16-24
  0x00, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f,       // attr registers 0-7
  0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f,       // attr registers 8-15
  0x01, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 12
  0x50, 0x1d, 0x10, 0x00, 0xa0, // bios data
  0x01, 0x0f, 0x00, 0x02, // sequencer registers
  0xe3, // misc output registers
  0x5f, 0x4f, 0x50, 0x82, 0x54, 0x80, 0x0b, 0x3e,       // crtc registers 0-7
  0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0xea, 0x8c, 0xdf, 0x28, 0x00, 0xe7, 0x04, 0xe3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,       // attr registers 0-7
  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,       // attr registers 8-15
  0x01, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 13
  0x28, 0x18, 0x08, 0x00, 0x20, // bios data
  0x01, 0x0f, 0x00, 0x0e, // sequencer registers
  0x63, // misc output registers
  0x5f, 0x4f, 0x50, 0x82, 0x54, 0x80, 0xbf, 0x1f,       // crtc registers 0-7
  0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x9c, 0x8e, 0x8f, 0x28, 0x40, 0x96, 0xb9, 0xa3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,       // attr registers 0-7
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,       // attr registers 8-15
  0x41, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x05, 0x0f, 0xff  // graphics registers 0-8
};

static byte video_parameter_table_ega[0x40*0x17]={
// video parameter table for mode 0 (cga emulation)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 1 (cga emulation)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 2 (cga emulation)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 3 (cga emulation)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 4
  0x28, 0x18, 0x08, 0x00, 0x40, // bios data
  0x09, 0x03, 0x00, 0x02, // sequencer registers
  0x63, // misc output registers
  0x37, 0x27, 0x28, 0x9a, 0x2b, 0x8a, 0x04, 0x11,       // crtc registers 0-7
  0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0xd4, 0x86, 0xc7, 0x14, 0x00, 0xd0, 0xfc, 0xb2, 0xff, // crtc registers 16-24
  0x00, 0x13, 0x15, 0x17, 0x02, 0x04, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x01, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x0f, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 5
  0x28, 0x18, 0x08, 0x00, 0x40, // bios data
  0x09, 0x03, 0x00, 0x02, // sequencer registers
  0x63, // misc output registers
  0x37, 0x27, 0x28, 0x9a, 0x2b, 0x8a, 0x04, 0x11,       // crtc registers 0-7
  0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0xd4, 0x86, 0xc7, 0x14, 0x00, 0xd0, 0xfc, 0xb2, 0xff, // crtc registers 16-24
  0x00, 0x13, 0x15, 0x17, 0x02, 0x04, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x01, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x0f, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 6
  0x50, 0x18, 0x08, 0x00, 0x40, // bios data
  0x01, 0x0f, 0x00, 0x06, // sequencer registers
  0x63, // misc output registers
  0x73, 0x4f, 0x50, 0x96, 0x54, 0x94, 0x04, 0x11,       // crtc registers 0-7
  0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0xd4, 0x86, 0xc7, 0x28, 0x00, 0xd0, 0xfc, 0xd2, 0xff, // crtc registers 16-24
  0x00, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,       // attr registers 0-7
  0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,       // attr registers 8-15
  0x01, 0x00, 0x01, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 7
  0x50, 0x18, 0x0e, 0x00, 0x10, // bios data
  0x00, 0x0f, 0x00, 0x03, // sequencer registers
  0xa2, // misc output registers
  0x73, 0x4f, 0x50, 0x96, 0x55, 0x95, 0xb6, 0x1f,       // crtc registers 0-7
  0x00, 0x4d, 0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x83, 0x85, 0x5d, 0x28, 0x0f, 0x63, 0xb1, 0xb3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x08, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 8
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 9
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode a
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode b
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode c
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode d
  0x28, 0x18, 0x08, 0x00, 0x20, // bios data
  0x09, 0x0f, 0x00, 0x06, // sequencer registers
  0x63, // misc output registers
  0x37, 0x27, 0x28, 0x9a, 0x2b, 0x8a, 0x04, 0x11,       // crtc registers 0-7
  0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0xd4, 0x86, 0xc7, 0x14, 0x00, 0xd0, 0xfc, 0xd3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x01, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode e
  0x50, 0x18, 0x08, 0x00, 0x40, // bios data
  0x01, 0x0f, 0x00, 0x06, // sequencer registers
  0x63, // misc output registers
  0x73, 0x4f, 0x50, 0x96, 0x54, 0x94, 0x04, 0x11,       // crtc registers 0-7
  0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0xd4, 0x86, 0xc7, 0x28, 0x00, 0xd0, 0xfc, 0xd3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x01, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode f (64k graphics memory)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode 10 (64k graphics memory)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// video parameter table for mode f (>64k graphics memory)
  0x50, 0x18, 0x0e, 0x00, 0x80, // bios data
  0x01, 0x0f, 0x00, 0x06, // sequencer registers
  0xa2, // misc output registers
  0x73, 0x4f, 0x50, 0x96, 0x54, 0x94, 0xb6, 0x1f,       // crtc registers 0-7
  0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x83, 0x85, 0x5d, 0x14, 0x0f, 0x63, 0xb1, 0x9b, 0xff, // crtc registers 16-24
  0x00, 0x08, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00,       // attr registers 0-7
  0x00, 0x08, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00,       // attr registers 8-15
  0x0b, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 10 (>64k graphics memory)
  0x50, 0x18, 0x0e, 0x00, 0x80, // bios data
  0x01, 0x0f, 0x00, 0x06, // sequencer registers
  0xa3, // misc output registers
  0x5b, 0x4f, 0x50, 0x9e, 0x54, 0x1c, 0x4e, 0x1f,       // crtc registers 0-7
  0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x83, 0x85, 0x5d, 0x14, 0x0f, 0x63, 0x49, 0x9b, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x01, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 0 (350 lines)
  0x28, 0x18, 0x0e, 0x00, 0x08, // bios data
  0x09, 0x0f, 0x00, 0x03, // sequencer registers
  0xa3, // misc output registers
  0x37, 0x27, 0x28, 0x9a, 0x2b, 0xaa, 0x04, 0x1f,       // crtc registers 0-7
  0x00, 0x4d, 0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x83, 0x85, 0x5d, 0x14, 0x0f, 0x63, 0xff, 0xb3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x08, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 1 (350 lines)
  0x28, 0x18, 0x0e, 0x00, 0x08, // bios data
  0x09, 0x0f, 0x00, 0x03, // sequencer registers
  0xa3, // misc output registers
  0x37, 0x27, 0x28, 0x9a, 0x2b, 0xaa, 0x04, 0x1f,       // crtc registers 0-7
  0x00, 0x4d, 0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x83, 0x85, 0x5d, 0x14, 0x0f, 0x63, 0xff, 0xb3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x08, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 2 (350 lines)
  0x50, 0x18, 0x0e, 0x00, 0x10, // bios data
  0x01, 0x0f, 0x00, 0x03, // sequencer registers
  0xa3, // misc output registers
  0x73, 0x4f, 0x50, 0x96, 0x55, 0x95, 0xb6, 0x1f,       // crtc registers 0-7
  0x00, 0x4d, 0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x83, 0x85, 0x5d, 0x28, 0x0f, 0x63, 0xb1, 0xb3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x08, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x0f, 0xff, // graphics registers 0-8
// video parameter table for mode 3 (350 lines)
  0x50, 0x18, 0x0e, 0x00, 0x10, // bios data
  0x01, 0x0f, 0x00, 0x03, // sequencer registers
  0xa3, // misc output registers
  0x73, 0x4f, 0x50, 0x96, 0x55, 0x95, 0xb6, 0x1f,       // crtc registers 0-7
  0x00, 0x4d, 0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00,       // crtc registers 8-15
  0x83, 0x85, 0x5d, 0x28, 0x0f, 0x63, 0xb1, 0xb3, 0xff, // crtc registers 16-24
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,       // attr registers 0-7
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,       // attr registers 8-15
  0x08, 0x00, 0x0f, 0x00, // attr registers 16-19
  0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x0f, 0xff // graphics registers 0-8
};

word INT10_SetupVideoParameterTable(word basepos) {
	word i;
	if (IS_VGA_ARCH) { //VGA+?
		for (i=0;i<0x40*0x1d;i++) {
			EMU_VGAROM[basepos+i] = video_parameter_table_vga[i]; //Load the table into the ROM!
		}
		return 0x40*0x1d;
	}
	//EGA?
	for (i=0;i<0x40*0x17;i++) {
		EMU_VGAROM[basepos+i] = video_parameter_table_ega[i];
	}
	return 0x40*0x17;
}

void INT10_SetupBasicVideoParameterTable(void) {
	Bit16u i;
	/* video parameter table at F000:F0A4 */
	RealSetVec(0x1d,0xF000, 0xF0A4); //Point the interrupt to our table in the main BIOS ROM!
	for (i = 0; i < sizeof(vparams); i++) {
		EMU_BIOS[0xF0A4+i] = vparams[i]; //Write our data to the BIOS ROM where it's supposed to be located!
	}
}