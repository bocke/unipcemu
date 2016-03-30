#include "headers/types.h" //Basic types!
#include "headers/hardware/vga/vga.h" //Precalculation support for CRT timing!
#include "headers/hardware/vga/vga_crtcontroller.h" //Our CRT timing we use!

byte int10_font_08[256 * 8] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x7e, 0x81, 0xa5, 0x81, 0xbd, 0x99, 0x81, 0x7e,
	0x7e, 0xff, 0xdb, 0xff, 0xc3, 0xe7, 0xff, 0x7e,
	0x6c, 0xfe, 0xfe, 0xfe, 0x7c, 0x38, 0x10, 0x00,
	0x10, 0x38, 0x7c, 0xfe, 0x7c, 0x38, 0x10, 0x00,
	0x38, 0x7c, 0x38, 0xfe, 0xfe, 0x7c, 0x38, 0x7c,
	0x10, 0x10, 0x38, 0x7c, 0xfe, 0x7c, 0x38, 0x7c,
	0x00, 0x00, 0x18, 0x3c, 0x3c, 0x18, 0x00, 0x00,
	0xff, 0xff, 0xe7, 0xc3, 0xc3, 0xe7, 0xff, 0xff,
	0x00, 0x3c, 0x66, 0x42, 0x42, 0x66, 0x3c, 0x00,
	0xff, 0xc3, 0x99, 0xbd, 0xbd, 0x99, 0xc3, 0xff,
	0x0f, 0x07, 0x0f, 0x7d, 0xcc, 0xcc, 0xcc, 0x78,
	0x3c, 0x66, 0x66, 0x66, 0x3c, 0x18, 0x7e, 0x18,
	0x3f, 0x33, 0x3f, 0x30, 0x30, 0x70, 0xf0, 0xe0,
	0x7f, 0x63, 0x7f, 0x63, 0x63, 0x67, 0xe6, 0xc0,
	0x99, 0x5a, 0x3c, 0xe7, 0xe7, 0x3c, 0x5a, 0x99,
	0x80, 0xe0, 0xf8, 0xfe, 0xf8, 0xe0, 0x80, 0x00,
	0x02, 0x0e, 0x3e, 0xfe, 0x3e, 0x0e, 0x02, 0x00,
	0x18, 0x3c, 0x7e, 0x18, 0x18, 0x7e, 0x3c, 0x18,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x00, 0x66, 0x00,
	0x7f, 0xdb, 0xdb, 0x7b, 0x1b, 0x1b, 0x1b, 0x00,
	0x3e, 0x63, 0x38, 0x6c, 0x6c, 0x38, 0xcc, 0x78,
	0x00, 0x00, 0x00, 0x00, 0x7e, 0x7e, 0x7e, 0x00,
	0x18, 0x3c, 0x7e, 0x18, 0x7e, 0x3c, 0x18, 0xff,
	0x18, 0x3c, 0x7e, 0x18, 0x18, 0x18, 0x18, 0x00,
	0x18, 0x18, 0x18, 0x18, 0x7e, 0x3c, 0x18, 0x00,
	0x00, 0x18, 0x0c, 0xfe, 0x0c, 0x18, 0x00, 0x00,
	0x00, 0x30, 0x60, 0xfe, 0x60, 0x30, 0x00, 0x00,
	0x00, 0x00, 0xc0, 0xc0, 0xc0, 0xfe, 0x00, 0x00,
	0x00, 0x24, 0x66, 0xff, 0x66, 0x24, 0x00, 0x00,
	0x00, 0x18, 0x3c, 0x7e, 0xff, 0xff, 0x00, 0x00,
	0x00, 0xff, 0xff, 0x7e, 0x3c, 0x18, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x30, 0x78, 0x78, 0x30, 0x30, 0x00, 0x30, 0x00,
	0x6c, 0x6c, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x6c, 0x6c, 0xfe, 0x6c, 0xfe, 0x6c, 0x6c, 0x00,
	0x30, 0x7c, 0xc0, 0x78, 0x0c, 0xf8, 0x30, 0x00,
	0x00, 0xc6, 0xcc, 0x18, 0x30, 0x66, 0xc6, 0x00,
	0x38, 0x6c, 0x38, 0x76, 0xdc, 0xcc, 0x76, 0x00,
	0x60, 0x60, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x18, 0x30, 0x60, 0x60, 0x60, 0x30, 0x18, 0x00,
	0x60, 0x30, 0x18, 0x18, 0x18, 0x30, 0x60, 0x00,
	0x00, 0x66, 0x3c, 0xff, 0x3c, 0x66, 0x00, 0x00,
	0x00, 0x30, 0x30, 0xfc, 0x30, 0x30, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x60,
	0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x00,
	0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0, 0x80, 0x00,
	0x7c, 0xc6, 0xce, 0xde, 0xf6, 0xe6, 0x7c, 0x00,
	0x30, 0x70, 0x30, 0x30, 0x30, 0x30, 0xfc, 0x00,
	0x78, 0xcc, 0x0c, 0x38, 0x60, 0xcc, 0xfc, 0x00,
	0x78, 0xcc, 0x0c, 0x38, 0x0c, 0xcc, 0x78, 0x00,
	0x1c, 0x3c, 0x6c, 0xcc, 0xfe, 0x0c, 0x1e, 0x00,
	0xfc, 0xc0, 0xf8, 0x0c, 0x0c, 0xcc, 0x78, 0x00,
	0x38, 0x60, 0xc0, 0xf8, 0xcc, 0xcc, 0x78, 0x00,
	0xfc, 0xcc, 0x0c, 0x18, 0x30, 0x30, 0x30, 0x00,
	0x78, 0xcc, 0xcc, 0x78, 0xcc, 0xcc, 0x78, 0x00,
	0x78, 0xcc, 0xcc, 0x7c, 0x0c, 0x18, 0x70, 0x00,
	0x00, 0x30, 0x30, 0x00, 0x00, 0x30, 0x30, 0x00,
	0x00, 0x30, 0x30, 0x00, 0x00, 0x30, 0x30, 0x60,
	0x18, 0x30, 0x60, 0xc0, 0x60, 0x30, 0x18, 0x00,
	0x00, 0x00, 0xfc, 0x00, 0x00, 0xfc, 0x00, 0x00,
	0x60, 0x30, 0x18, 0x0c, 0x18, 0x30, 0x60, 0x00,
	0x78, 0xcc, 0x0c, 0x18, 0x30, 0x00, 0x30, 0x00,
	0x7c, 0xc6, 0xde, 0xde, 0xde, 0xc0, 0x78, 0x00,
	0x30, 0x78, 0xcc, 0xcc, 0xfc, 0xcc, 0xcc, 0x00,
	0xfc, 0x66, 0x66, 0x7c, 0x66, 0x66, 0xfc, 0x00,
	0x3c, 0x66, 0xc0, 0xc0, 0xc0, 0x66, 0x3c, 0x00,
	0xf8, 0x6c, 0x66, 0x66, 0x66, 0x6c, 0xf8, 0x00,
	0xfe, 0x62, 0x68, 0x78, 0x68, 0x62, 0xfe, 0x00,
	0xfe, 0x62, 0x68, 0x78, 0x68, 0x60, 0xf0, 0x00,
	0x3c, 0x66, 0xc0, 0xc0, 0xce, 0x66, 0x3e, 0x00,
	0xcc, 0xcc, 0xcc, 0xfc, 0xcc, 0xcc, 0xcc, 0x00,
	0x78, 0x30, 0x30, 0x30, 0x30, 0x30, 0x78, 0x00,
	0x1e, 0x0c, 0x0c, 0x0c, 0xcc, 0xcc, 0x78, 0x00,
	0xe6, 0x66, 0x6c, 0x78, 0x6c, 0x66, 0xe6, 0x00,
	0xf0, 0x60, 0x60, 0x60, 0x62, 0x66, 0xfe, 0x00,
	0xc6, 0xee, 0xfe, 0xfe, 0xd6, 0xc6, 0xc6, 0x00,
	0xc6, 0xe6, 0xf6, 0xde, 0xce, 0xc6, 0xc6, 0x00,
	0x38, 0x6c, 0xc6, 0xc6, 0xc6, 0x6c, 0x38, 0x00,
	0xfc, 0x66, 0x66, 0x7c, 0x60, 0x60, 0xf0, 0x00,
	0x78, 0xcc, 0xcc, 0xcc, 0xdc, 0x78, 0x1c, 0x00,
	0xfc, 0x66, 0x66, 0x7c, 0x6c, 0x66, 0xe6, 0x00,
	0x78, 0xcc, 0xe0, 0x70, 0x1c, 0xcc, 0x78, 0x00,
	0xfc, 0xb4, 0x30, 0x30, 0x30, 0x30, 0x78, 0x00,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xfc, 0x00,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x78, 0x30, 0x00,
	0xc6, 0xc6, 0xc6, 0xd6, 0xfe, 0xee, 0xc6, 0x00,
	0xc6, 0xc6, 0x6c, 0x38, 0x38, 0x6c, 0xc6, 0x00,
	0xcc, 0xcc, 0xcc, 0x78, 0x30, 0x30, 0x78, 0x00,
	0xfe, 0xc6, 0x8c, 0x18, 0x32, 0x66, 0xfe, 0x00,
	0x78, 0x60, 0x60, 0x60, 0x60, 0x60, 0x78, 0x00,
	0xc0, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x02, 0x00,
	0x78, 0x18, 0x18, 0x18, 0x18, 0x18, 0x78, 0x00,
	0x10, 0x38, 0x6c, 0xc6, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
	0x30, 0x30, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x78, 0x0c, 0x7c, 0xcc, 0x76, 0x00,
	0xe0, 0x60, 0x60, 0x7c, 0x66, 0x66, 0xdc, 0x00,
	0x00, 0x00, 0x78, 0xcc, 0xc0, 0xcc, 0x78, 0x00,
	0x1c, 0x0c, 0x0c, 0x7c, 0xcc, 0xcc, 0x76, 0x00,
	0x00, 0x00, 0x78, 0xcc, 0xfc, 0xc0, 0x78, 0x00,
	0x38, 0x6c, 0x60, 0xf0, 0x60, 0x60, 0xf0, 0x00,
	0x00, 0x00, 0x76, 0xcc, 0xcc, 0x7c, 0x0c, 0xf8,
	0xe0, 0x60, 0x6c, 0x76, 0x66, 0x66, 0xe6, 0x00,
	0x30, 0x00, 0x70, 0x30, 0x30, 0x30, 0x78, 0x00,
	0x0c, 0x00, 0x0c, 0x0c, 0x0c, 0xcc, 0xcc, 0x78,
	0xe0, 0x60, 0x66, 0x6c, 0x78, 0x6c, 0xe6, 0x00,
	0x70, 0x30, 0x30, 0x30, 0x30, 0x30, 0x78, 0x00,
	0x00, 0x00, 0xcc, 0xfe, 0xfe, 0xd6, 0xc6, 0x00,
	0x00, 0x00, 0xf8, 0xcc, 0xcc, 0xcc, 0xcc, 0x00,
	0x00, 0x00, 0x78, 0xcc, 0xcc, 0xcc, 0x78, 0x00,
	0x00, 0x00, 0xdc, 0x66, 0x66, 0x7c, 0x60, 0xf0,
	0x00, 0x00, 0x76, 0xcc, 0xcc, 0x7c, 0x0c, 0x1e,
	0x00, 0x00, 0xdc, 0x76, 0x66, 0x60, 0xf0, 0x00,
	0x00, 0x00, 0x7c, 0xc0, 0x78, 0x0c, 0xf8, 0x00,
	0x10, 0x30, 0x7c, 0x30, 0x30, 0x34, 0x18, 0x00,
	0x00, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0x76, 0x00,
	0x00, 0x00, 0xcc, 0xcc, 0xcc, 0x78, 0x30, 0x00,
	0x00, 0x00, 0xc6, 0xd6, 0xfe, 0xfe, 0x6c, 0x00,
	0x00, 0x00, 0xc6, 0x6c, 0x38, 0x6c, 0xc6, 0x00,
	0x00, 0x00, 0xcc, 0xcc, 0xcc, 0x7c, 0x0c, 0xf8,
	0x00, 0x00, 0xfc, 0x98, 0x30, 0x64, 0xfc, 0x00,
	0x1c, 0x30, 0x30, 0xe0, 0x30, 0x30, 0x1c, 0x00,
	0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x00,
	0xe0, 0x30, 0x30, 0x1c, 0x30, 0x30, 0xe0, 0x00,
	0x76, 0xdc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x10, 0x38, 0x6c, 0xc6, 0xc6, 0xfe, 0x00,
	0x78, 0xcc, 0xc0, 0xcc, 0x78, 0x18, 0x0c, 0x78,
	0x00, 0xcc, 0x00, 0xcc, 0xcc, 0xcc, 0x7e, 0x00,
	0x1c, 0x00, 0x78, 0xcc, 0xfc, 0xc0, 0x78, 0x00,
	0x7e, 0xc3, 0x3c, 0x06, 0x3e, 0x66, 0x3f, 0x00,
	0xcc, 0x00, 0x78, 0x0c, 0x7c, 0xcc, 0x7e, 0x00,
	0xe0, 0x00, 0x78, 0x0c, 0x7c, 0xcc, 0x7e, 0x00,
	0x30, 0x30, 0x78, 0x0c, 0x7c, 0xcc, 0x7e, 0x00,
	0x00, 0x00, 0x78, 0xc0, 0xc0, 0x78, 0x0c, 0x38,
	0x7e, 0xc3, 0x3c, 0x66, 0x7e, 0x60, 0x3c, 0x00,
	0xcc, 0x00, 0x78, 0xcc, 0xfc, 0xc0, 0x78, 0x00,
	0xe0, 0x00, 0x78, 0xcc, 0xfc, 0xc0, 0x78, 0x00,
	0xcc, 0x00, 0x70, 0x30, 0x30, 0x30, 0x78, 0x00,
	0x7c, 0xc6, 0x38, 0x18, 0x18, 0x18, 0x3c, 0x00,
	0xe0, 0x00, 0x70, 0x30, 0x30, 0x30, 0x78, 0x00,
	0xc6, 0x38, 0x6c, 0xc6, 0xfe, 0xc6, 0xc6, 0x00,
	0x30, 0x30, 0x00, 0x78, 0xcc, 0xfc, 0xcc, 0x00,
	0x1c, 0x00, 0xfc, 0x60, 0x78, 0x60, 0xfc, 0x00,
	0x00, 0x00, 0x7f, 0x0c, 0x7f, 0xcc, 0x7f, 0x00,
	0x3e, 0x6c, 0xcc, 0xfe, 0xcc, 0xcc, 0xce, 0x00,
	0x78, 0xcc, 0x00, 0x78, 0xcc, 0xcc, 0x78, 0x00,
	0x00, 0xcc, 0x00, 0x78, 0xcc, 0xcc, 0x78, 0x00,
	0x00, 0xe0, 0x00, 0x78, 0xcc, 0xcc, 0x78, 0x00,
	0x78, 0xcc, 0x00, 0xcc, 0xcc, 0xcc, 0x7e, 0x00,
	0x00, 0xe0, 0x00, 0xcc, 0xcc, 0xcc, 0x7e, 0x00,
	0x00, 0xcc, 0x00, 0xcc, 0xcc, 0x7c, 0x0c, 0xf8,
	0xc3, 0x18, 0x3c, 0x66, 0x66, 0x3c, 0x18, 0x00,
	0xcc, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0x78, 0x00,
	0x18, 0x18, 0x7e, 0xc0, 0xc0, 0x7e, 0x18, 0x18,
	0x38, 0x6c, 0x64, 0xf0, 0x60, 0xe6, 0xfc, 0x00,
	0xcc, 0xcc, 0x78, 0xfc, 0x30, 0xfc, 0x30, 0x30,
	0xf8, 0xcc, 0xcc, 0xfa, 0xc6, 0xcf, 0xc6, 0xc7,
	0x0e, 0x1b, 0x18, 0x3c, 0x18, 0x18, 0xd8, 0x70,
	0x1c, 0x00, 0x78, 0x0c, 0x7c, 0xcc, 0x7e, 0x00,
	0x38, 0x00, 0x70, 0x30, 0x30, 0x30, 0x78, 0x00,
	0x00, 0x1c, 0x00, 0x78, 0xcc, 0xcc, 0x78, 0x00,
	0x00, 0x1c, 0x00, 0xcc, 0xcc, 0xcc, 0x7e, 0x00,
	0x00, 0xf8, 0x00, 0xf8, 0xcc, 0xcc, 0xcc, 0x00,
	0xfc, 0x00, 0xcc, 0xec, 0xfc, 0xdc, 0xcc, 0x00,
	0x3c, 0x6c, 0x6c, 0x3e, 0x00, 0x7e, 0x00, 0x00,
	0x38, 0x6c, 0x6c, 0x38, 0x00, 0x7c, 0x00, 0x00,
	0x30, 0x00, 0x30, 0x60, 0xc0, 0xcc, 0x78, 0x00,
	0x00, 0x00, 0x00, 0xfc, 0xc0, 0xc0, 0x00, 0x00,
	0x00, 0x00, 0x00, 0xfc, 0x0c, 0x0c, 0x00, 0x00,
	0xc3, 0xc6, 0xcc, 0xde, 0x33, 0x66, 0xcc, 0x0f,
	0xc3, 0xc6, 0xcc, 0xdb, 0x37, 0x6f, 0xcf, 0x03,
	0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x18, 0x00,
	0x00, 0x33, 0x66, 0xcc, 0x66, 0x33, 0x00, 0x00,
	0x00, 0xcc, 0x66, 0x33, 0x66, 0xcc, 0x00, 0x00,
	0x22, 0x88, 0x22, 0x88, 0x22, 0x88, 0x22, 0x88,
	0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa,
	0xdb, 0x77, 0xdb, 0xee, 0xdb, 0x77, 0xdb, 0xee,
	0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
	0x18, 0x18, 0x18, 0x18, 0xf8, 0x18, 0x18, 0x18,
	0x18, 0x18, 0xf8, 0x18, 0xf8, 0x18, 0x18, 0x18,
	0x36, 0x36, 0x36, 0x36, 0xf6, 0x36, 0x36, 0x36,
	0x00, 0x00, 0x00, 0x00, 0xfe, 0x36, 0x36, 0x36,
	0x00, 0x00, 0xf8, 0x18, 0xf8, 0x18, 0x18, 0x18,
	0x36, 0x36, 0xf6, 0x06, 0xf6, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x00, 0x00, 0xfe, 0x06, 0xf6, 0x36, 0x36, 0x36,
	0x36, 0x36, 0xf6, 0x06, 0xfe, 0x00, 0x00, 0x00,
	0x36, 0x36, 0x36, 0x36, 0xfe, 0x00, 0x00, 0x00,
	0x18, 0x18, 0xf8, 0x18, 0xf8, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xf8, 0x18, 0x18, 0x18,
	0x18, 0x18, 0x18, 0x18, 0x1f, 0x00, 0x00, 0x00,
	0x18, 0x18, 0x18, 0x18, 0xff, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0x18, 0x18, 0x18,
	0x18, 0x18, 0x18, 0x18, 0x1f, 0x18, 0x18, 0x18,
	0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00,
	0x18, 0x18, 0x18, 0x18, 0xff, 0x18, 0x18, 0x18,
	0x18, 0x18, 0x1f, 0x18, 0x1f, 0x18, 0x18, 0x18,
	0x36, 0x36, 0x36, 0x36, 0x37, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x37, 0x30, 0x3f, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x3f, 0x30, 0x37, 0x36, 0x36, 0x36,
	0x36, 0x36, 0xf7, 0x00, 0xff, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xff, 0x00, 0xf7, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x37, 0x30, 0x37, 0x36, 0x36, 0x36,
	0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00,
	0x36, 0x36, 0xf7, 0x00, 0xf7, 0x36, 0x36, 0x36,
	0x18, 0x18, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00,
	0x36, 0x36, 0x36, 0x36, 0xff, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xff, 0x00, 0xff, 0x18, 0x18, 0x18,
	0x00, 0x00, 0x00, 0x00, 0xff, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x3f, 0x00, 0x00, 0x00,
	0x18, 0x18, 0x1f, 0x18, 0x1f, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1f, 0x18, 0x1f, 0x18, 0x18, 0x18,
	0x00, 0x00, 0x00, 0x00, 0x3f, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0xff, 0x36, 0x36, 0x36,
	0x18, 0x18, 0xff, 0x18, 0xff, 0x18, 0x18, 0x18,
	0x18, 0x18, 0x18, 0x18, 0xf8, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x1f, 0x18, 0x18, 0x18,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x76, 0xdc, 0xc8, 0xdc, 0x76, 0x00,
	0x00, 0x78, 0xcc, 0xf8, 0xcc, 0xf8, 0xc0, 0xc0,
	0x00, 0xfc, 0xcc, 0xc0, 0xc0, 0xc0, 0xc0, 0x00,
	0x00, 0xfe, 0x6c, 0x6c, 0x6c, 0x6c, 0x6c, 0x00,
	0xfc, 0xcc, 0x60, 0x30, 0x60, 0xcc, 0xfc, 0x00,
	0x00, 0x00, 0x7e, 0xd8, 0xd8, 0xd8, 0x70, 0x00,
	0x00, 0x66, 0x66, 0x66, 0x66, 0x7c, 0x60, 0xc0,
	0x00, 0x76, 0xdc, 0x18, 0x18, 0x18, 0x18, 0x00,
	0xfc, 0x30, 0x78, 0xcc, 0xcc, 0x78, 0x30, 0xfc,
	0x38, 0x6c, 0xc6, 0xfe, 0xc6, 0x6c, 0x38, 0x00,
	0x38, 0x6c, 0xc6, 0xc6, 0x6c, 0x6c, 0xee, 0x00,
	0x1c, 0x30, 0x18, 0x7c, 0xcc, 0xcc, 0x78, 0x00,
	0x00, 0x00, 0x7e, 0xdb, 0xdb, 0x7e, 0x00, 0x00,
	0x06, 0x0c, 0x7e, 0xdb, 0xdb, 0x7e, 0x60, 0xc0,
	0x38, 0x60, 0xc0, 0xf8, 0xc0, 0x60, 0x38, 0x00,
	0x78, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x00,
	0x00, 0xfc, 0x00, 0xfc, 0x00, 0xfc, 0x00, 0x00,
	0x30, 0x30, 0xfc, 0x30, 0x30, 0x00, 0xfc, 0x00,
	0x60, 0x30, 0x18, 0x30, 0x60, 0x00, 0xfc, 0x00,
	0x18, 0x30, 0x60, 0x30, 0x18, 0x00, 0xfc, 0x00,
	0x0e, 0x1b, 0x1b, 0x18, 0x18, 0x18, 0x18, 0x18,
	0x18, 0x18, 0x18, 0x18, 0x18, 0xd8, 0xd8, 0x70,
	0x30, 0x30, 0x00, 0xfc, 0x00, 0x30, 0x30, 0x00,
	0x00, 0x76, 0xdc, 0x00, 0x76, 0xdc, 0x00, 0x00,
	0x38, 0x6c, 0x6c, 0x38, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
	0x0f, 0x0c, 0x0c, 0x0c, 0xec, 0x6c, 0x3c, 0x1c,
	0x78, 0x6c, 0x6c, 0x6c, 0x6c, 0x00, 0x00, 0x00,
	0x70, 0x18, 0x30, 0x60, 0x78, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x3c, 0x3c, 0x3c, 0x3c, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

OPTINLINE static byte reverse8_CGA(register byte b) { //Reverses byte value bits!
	b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4); //Swap 4 high and low bits!
	b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2); //Swap 2 high and low bits of both nibbles!
	b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1); //Swap odd and even bits!
	return b;
}

byte CGA_reversedinit = 1;
byte int10_font_08_reversed[256*8]; //Full font, reversed for optimized display!

byte getcharxy_CGA(byte character, byte x, byte y) //Retrieve a characters x,y pixel on/off from the unmodified 8x8 table!
{
	static word lastcharinfo = 0; //attribute|character, bit31=Set?
	static byte lastrow = 0; //The last loaded row!
	register word location;

	//Don't do range checks, we're always within range (because of GPU_textcalcpixel)!
	location = 0x8000 | (character << 3) | y; //The location to look up!

	if (lastcharinfo != location) //Last row not yet loaded?
	{
		lastrow = int10_font_08_reversed[(lastcharinfo = location)^0x8000]; //Read the row from the character generator to use! Also reverse the bits for faster usage, which is already done!
	}

	//Take the pixel we need!
	return ((lastrow>>x)&1); //Give result from the reversed data!
}

void fillCGAfont()
{
	if (CGA_reversedinit) //Need to initialise?
	{
		word row;
		for (row=0;row<sizeof(int10_font_08_reversed);row++)
		{
			int10_font_08_reversed[row] = reverse8_CGA(int10_font_08[row]);
		}
		CGA_reversedinit = 0; //Finished initialising!
	}
}

byte CGA_is_hsync(VGA_Type *VGA, word x) //Are we vsync?
{
	if ((x>=((VGA->registers->CGARegisters[2]&0x7F)<<3)) && (x<(((VGA->registers->CGARegisters[2]&0x7F)<<3)+(VGA->registers->CGARegisters[3]<<3)))) //Horizontal sync?
	{
		return 1; //Horizontal sync!
	}
	return 0;
}


word get_display_CGA_x(VGA_Type *VGA, word x)
{
	word result=0;
	word column=x; //Unpatched x value!
	if (!x)	result |= VGA_SIGNAL_HRETRACEEND|VGA_SIGNAL_HBLANKEND; //Horizontal retrace&blank is finished now!
	column >>= 3; //Divide by 8 to get the character clock!
	if (column>((VGA->registers->CGARegisters[0]&0x7F))) //Past total specified?
	{
		result |= VGA_SIGNAL_HTOTAL; //End of display: start the next frame!
		if (CGA_is_hsync(VGA,x-(VGA->registers->CGARegisters[3]<<3)) && x) //HSync within range?
		{
			result |= VGA_SIGNAL_HSYNCRESET; //Reset HSync!
		}
	}
	if (CGA_is_hsync(VGA,x)) //Horizontal sync?
	{
		result |= VGA_SIGNAL_HRETRACESTART; //Start horizontal sync!
	}
	else if (x && CGA_is_hsync(VGA,x-1)) //Previous was hsync?
	{
		if (column>((VGA->registers->CGARegisters[0]&0x7F))) //HSync out of range?
		{
			result |= VGA_SIGNAL_HSYNCRESET; //Reset HSync!
		}
		result |= VGA_SIGNAL_HRETRACEEND; //End horizontal sync!
	}
	if (column<VGA->registers->CGARegisters[1]) //Are we displayed?
	{
		result |= VGA_HACTIVEDISPLAY; //Horizontal displayed!
	}
	else
	{
		result |= VGA_OVERSCAN; //We're overscan by default!
	}
	return result; //Give the signal!
}

byte CGA_is_vsync(VGA_Type *VGA, word y, byte charheight) //Are we vsync?
{
	if ((y>=(VGA->registers->CGARegisters[7]&0x7F)*charheight) && (y<(((VGA->registers->CGARegisters[7]&0x7F)*charheight)+0x10))) //Vertical sync? It's always 16 lines!
	{
		return 1; //Vertical sync!
	}
	return 0;
}

word get_display_CGA_y(VGA_Type *VGA, word y)
{
	word result=0;
	if (!y) result |= VGA_SIGNAL_VRETRACEEND|VGA_SIGNAL_VBLANKEND; //End vertical retrace&blank if still there!
	word row;
	byte charheight;
	charheight = (VGA->registers->CGARegisters[9]&0x1F)+1; //Character height!
	row = y;
	row /= charheight; //The row we're at!
	if (row>(VGA->registers->CGARegisters[4]&0x7F)) //Past total specified?
	{
		if ((((VGA->registers->CGARegisters[4]&0x7F)*charheight)+VGA->registers->CGARegisters[5])<y) //Vertical total adjustment reaced?
		{
			result |= VGA_SIGNAL_VTOTAL; //End of display: start the next frame!
			if (CGA_is_vsync(VGA,y-16,charheight) && y) //VSync within range?
			{
				result |= VGA_SIGNAL_VSYNCRESET; //Reset VSync!
			}
		}
		result |= VGA_SIGNAL_VBLANKSTART; //We're blanking always after end of display!
	}
	else //Normal display?
	{
		if (row<(VGA->registers->CGARegisters[6]&0x7F)) //Active display?
		{
			result |= VGA_VACTIVEDISPLAY; //We're active display!
		}
		else
		{
			result |= VGA_OVERSCAN; //We're overscan by default!
		}
	}

	if (CGA_is_vsync(VGA,y,charheight)) //Vertical sync?
	{
		result |= VGA_SIGNAL_VRETRACESTART; //Vertical sync is simply blanking space!
	}
	else if (y && CGA_is_vsync(VGA,y-1,charheight)) //Previous was vsync?
	{
		if (row>(VGA->registers->CGARegisters[4]&0x7F)) //VSync end out of range?
		{
			result |= VGA_SIGNAL_VSYNCRESET; //Reset VSync!
		}
		result |= VGA_SIGNAL_VRETRACEEND; //End of retrace period, if any!
	}
	return result; //Give the signal!
}