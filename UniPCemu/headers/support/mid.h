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

#ifndef MID_H
#define MID_H

#include "headers/types.h" //Basic types!

//MIDI file player support!

byte playMIDIFile(char *filename, byte showinfo); //Play a MIDI file, CIRCLE to stop playback! Cancelled/error loading returns 0, 1 on success playing.
void updateMIDIPlayer(DOUBLE timepassed); //Update the running MIDI player!

#endif