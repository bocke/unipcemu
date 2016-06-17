#ifndef VGA_VRAM_H
#define VGA_VRAM_H

#include "headers/types.h" //Basic types!
#include "headers/hardware/vga/vga.h" //VGA basics!

byte readVRAMplane(VGA_Type *VGA, byte plane, uint_32 offset); //Read from a VRAM plane!
void writeVRAMplane(VGA_Type *VGA, byte plane, uint_32 offset, byte value); //Write to a VRAM plane!

//Direct access to 32-bit VRAM planes!
#define VGA_VRAMDIRECTPLANAR(VGA,vramlocation) *((uint_32 *)(&VGA->VRAM[(vramlocation<<2)&VGA->precalcs.VMemMask]))
#define VGA_VRAMDIRECT(VGA,vramlocation) VGA->VRAM[vramlocation&VGA->precalcs.VMemMask]

#endif