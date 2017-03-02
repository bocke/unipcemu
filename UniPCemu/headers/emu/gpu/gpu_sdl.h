#ifndef GPU_SDL_H
#define GPU_SDL_H

#include "headers/emu/gpu/gpu.h" //GPU typedefs&SDL etc.

//Flags for SDL_Userdata:

//We're a dirty surface?
#define SDL_FLAG_DIRTY 1
//We're a no-delete surface (like a surface allocated with SDL_SetVideoMode) or no-delete pixels (a surface based upon another surface or allocation)
#define SDL_FLAG_NODELETE_PIXELS 4
#define SDL_FLAG_NODELETE 2
typedef struct {
	SDL_Surface *sdllayer; //The surface itself!
	byte flags; //Our flags!
	SDL_sem *lock;

	//Extra stuff for optimizing resizing!
	int *hrowincrements, *vrowincrements;
	uint_32 hrowincrements_precalcs, vrowincrements_precalcs; //Information about source and destination surfaces!
	uint_32 hrowincrements_size, vrowincrements_size; //The size of the horizontal and vertical row increment sizes!
} GPU_SDL_Surface; //Our userdata!

GPU_SDL_Surface *getSurfaceWrapper(SDL_Surface *surface); //Retrieves a surface wrapper (for the GPU HW Surface only!)

void matchColorKeys(const GPU_SDL_Surface* src, GPU_SDL_Surface* dest );

byte check_surface(GPU_SDL_Surface *surface); //Is this surface valid to use?

//Basic pixel manipulation:
uint_32 get_pixel(GPU_SDL_Surface* surface, const int x, const int y );
void put_pixel(GPU_SDL_Surface *surface, const int x, const int y, const Uint32 pixel );

//Pixel row pitch
uint_32 get_pixelrow_pitch(GPU_SDL_Surface *surface); //Get the difference between two rows!

//Pixel row from a certain pixel pointer
void *get_pixel_ptr(GPU_SDL_Surface *surface, const int y, const int x);

//Row functions, by me!
uint_32 *get_pixel_row(GPU_SDL_Surface *surface, const int y, const int x);
void put_pixel_row(GPU_SDL_Surface *surface, const int y, uint_32 rowsize, uint_32 *pixels, int center, uint_32 row_start, word *xstart); //Based upon above, but for whole rows at once!

//Full surface operations:
void registerSurface(GPU_SDL_Surface *surface, char *name, byte allowsurfacerelease); //Register a surface to be able to cleanup!
GPU_SDL_Surface *createSurface(int columns, int rows); //Create a 32BPP surface!
GPU_SDL_Surface *createSurfaceFromPixels(int columns, int rows, void *pixels, uint_32 pixelpitch); //Create a 32BPP surface, but from an allocated/solid buffer (not deallocated when freed)! Can be used for persistent buffers (always there, like the GPU screen buffer itself)
GPU_SDL_Surface *freeSurface(GPU_SDL_Surface *surface);
void safeFlip(GPU_SDL_Surface *surface); //Safe flipping (non-null)
byte resizeImage(GPU_SDL_Surface *img, GPU_SDL_Surface **dstimg, const uint_32 newwidth, const uint_32 newheight, int aspectratio);

void calcResize(int aspectratio, uint_32 originalwidth, uint_32 originalheight, uint_32 newwidth, uint_32 newheight, uint_32 *n_width, uint_32 *n_height, byte is_renderer); //Calculates resize dimensions!

#endif