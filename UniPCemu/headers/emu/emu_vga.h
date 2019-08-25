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

#ifndef __EMU_VGA_H
#define __EMU_VGA_H

void EMU_update_VGA_Settings(); //Update the VGA settings for the emulator!
void VGA_initTimer(); //Initialise the timer before running!
void updateVGA(DOUBLE timepassed, uint_32 MHZ14passed); //Tick the timer for the CPU accurate cycle emulation!

#endif