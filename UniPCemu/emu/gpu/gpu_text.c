#include "headers/emu/gpu/gpu.h" //Basic GPU!
#include "headers/emu/gpu/gpu_text.h" //Our prototypes!
#include "headers/emu/gpu/gpu_sdl.h" //For rendering!
#include "headers/interrupts/textmodedata.h" //Fonts for rendering!
#include "headers/support/zalloc.h" //Zero allocation support!
#include "headers/support/log.h" //Logging support!
#include "headers/support/highrestimer.h" //High resolution timer!

#define __HW_DISABLED 0

//Clickable bit values (used internally)!
//Clickable character!
#define CLICKABLE_CLICKABLE 1
//Mouse has been pressed!
#define CLICKABLE_BUTTONDOWN 2
//Mouse has clicked!
#define CLICKABLE_CLICKED 4

extern GPU_SDL_Surface *rendersurface; //The PSP's surface to use when flipping!
extern byte allcleared;

word TEXT_xdelta = 0;
word TEXT_ydelta = 0; //Delta x,y!

#ifdef ANDROID
//We're using adaptive text surfaces for supported devices!
#define ADAPTIVETEXT
#endif

float render_xfactor=1.0f, render_yfactor=1.0f; //X and Y factor during rendering!
float render_xfactorreverse = 1.0, render_yfactorreverse = 1.0; //X and Y factor during mouse/touch input!

OPTINLINE static byte reverse8(INLINEREGISTER byte b) { //Reverses byte value bits!
	b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4); //Swap 4 high and low bits!
	b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2); //Swap 2 high and low bits of both nibbles!
	b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1); //Swap odd and even bits!
	return b;
}

byte reversedinit = 1;
byte int10_font_08_reversed[256*8]; //Full font, reversed for optimized display!

OPTINLINE static byte getcharxy_8(byte character, word y) //Retrieve a characters x,y pixel on/off from the unmodified 8x8 table!
{
	static word lastcharinfo = 0; //attribute|character, bit31=Set?
	static byte lastrow = 0; //The last loaded row!
	INLINEREGISTER word location;
	INLINEREGISTER byte effectiverow; //Effective row!

	if (character) //Non-empty character?
	{
		if (character!=0x20) //Not space, which is also empty?
		{
			//Don't do range checks, we're always within range!
			location = 0x8000|(character << 3)|y; //The location to look up!

			if (location!=lastcharinfo) //Last row not yet loaded?
			{
				lastcharinfo = location; //Load the new location!
				location ^= 0x8000; //Disable our used bit!
				lastrow = int10_font_08_reversed[location]; //Read the row from the character generator to use! Also reverse the bits for faster usage, which is already done!
			}
			effectiverow = lastrow; //The row to use!
		}
		else
		{
			effectiverow = 0; //Nothing loaded!
		}
	}
	else
	{
		effectiverow = 0; //Nothing loaded!
	}

	//Take the pixel we need!
	return effectiverow; //Give result from the reversed data!
}

OPTINLINE static uint_32 GPU_textgetcolor(GPU_TEXTSURFACE *surface, int x, int y, int border) //border = either border(1) or font(0)
{
	if (allcleared) return 0; //Abort when all is cleared!
	if ((x<0) || (y<0) || (x >= GPU_TEXTPIXELSX) || (y >= GPU_TEXTPIXELSY)) return TRANSPARENTPIXEL; //Invalid=Transparant!
	return border ? surface->border[y>>3][x>>3] : surface->font[y>>3][x>>3]; //Give the border or font of the character!
}

//Get direct pixel from handler (overflow handled)!
#define GPU_textget_pixel(surface,x,y) surface->fontpixels[(y<<9)|x]
#define GPU_textget_pixelrowptr(surface,y) &surface->fontpixels[y<<9]

OPTINLINE static void updateDirty(GPU_TEXTSURFACE *surface, int fx, int fy)
{
	byte xmin, xmax; //Top/bottom maximum reached?
	byte backpixel; //Are we a background pixel?
	//Undirty!
	if (unlikely(GPU_textget_pixel(surface,fx,fy))) //Font?
	{
		surface->notdirty[(fy<<9)|fx] = GPU_textgetcolor(surface,fx,fy,0); //Font!
	}
	else
	{
		INLINEREGISTER int fx2, fy2;

		backpixel = 0; //Default transparent background pixel!

		fx2 = fx; //Load the ...
		fy2 = fy; //Coordinates to check!
	
		//We're background/transparent!
		//{ 1,1 },{ 1,0 },{ 0,1 },{ 1,-1 },{ -1,1 },{ 0,-1 },{ -1,0 },{ -1,-1 }

		xmin = (fx==0); //Min not available?
		xmax = (fx>=(GPU_TEXTPIXELSX-1)); //Max not available?

		--fx2;
		--fy2; //-1,-1
		if (unlikely(fy==0)) goto skipfirst; //Vertical first row available?
		{
			if (unlikely(xmin)) goto skipmin1;
			{
				if (unlikely(GPU_textget_pixel(surface, fx2, fy2))) //Border?
				{
					backpixel = 1;
					goto finishtextrendering; //We're finished!
				}
			}

			skipmin1:
			//Middle column is always valid!
			++fx2; //0,-1
			if (unlikely(GPU_textget_pixel(surface, fx2, fy2))) //Border?
			{
				backpixel = 1;
				goto finishtextrendering; //We're finished!
			}

			if (unlikely(xmax)) goto skipmax1;
			{
				++fx2; //1,-1
				if (unlikely(GPU_textget_pixel(surface, fx2, fy2))) //Border?
				{
					backpixel = 1;
					goto finishtextrendering; //We're finished!
				}
				--fx2; //0,-1
			}
			skipmax1:
			--fx2; //-1,0
		}

		skipfirst:
		//Middle row? It's always valid!
		++fy2;
		if (unlikely(xmin)) goto skipmin2;
		{
			if (unlikely(GPU_textget_pixel(surface, fx2, fy2))) //Border?
			{
				backpixel = 1;
				goto finishtextrendering; //We're finished!
			}
		}

		skipmin2:
		if (unlikely(xmax)) goto skipmax2;
		{
			++fx2;
			++fx2; //1,0
			if (unlikely(GPU_textget_pixel(surface, fx2, fy2))) //Border?
			{
				backpixel = 1;
				goto finishtextrendering; //We're finished!
			}
			--fx2;
			--fx2; //-1,0
		}
		
		skipmax2:
		if (unlikely(fy==(GPU_TEXTPIXELSY-1))) goto finishtextrendering; //Vertical bottom row available?
		{
			++fy2;
			if (unlikely(xmin)) goto skipmin3;
			{
				if (unlikely(GPU_textget_pixel(surface, fx2, fy2))) //Border?
				{
					backpixel = 1;
					goto finishtextrendering; //We're finished!
				}
			}
			skipmin3:
			//Middle column is always valid!
			++fx2; //0,1
			if (unlikely(GPU_textget_pixel(surface, fx2, fy2))) //Border?
			{
				backpixel = 1;
				goto finishtextrendering; //We're finished!
			}

			if (unlikely(xmax)) goto finishtextrendering;
			{
				++fx2; //1,1
				if (unlikely(GPU_textget_pixel(surface, fx2, fy2))) //Border?
				{
					backpixel = 1;
				}
			}
		}

		finishtextrendering:
		//We're transparent or background!
		surface->notdirty[(fy<<9)|fx] = backpixel?GPU_textgetcolor(surface, fx, fy, 1):TRANSPARENTPIXEL; //Background or Transparent instead!
	}
}

//Basic Container/wrapper support
void freeTextSurfacePtr(void **ptr, uint_32 size, SDL_sem *lock) //Free a pointer (used internally only) allocated with nzalloc/zalloc and our internal functions!
{
	GPU_TEXTSURFACE *tsurface = (GPU_TEXTSURFACE *)*ptr; //Take the surface out of the pointer!
	if (tsurface->horizontalprecalcs) //Gotten horizontal precalcs?
	{
		freez((void **)&tsurface->horizontalprecalcs,tsurface->horizontalprecalcssize,"TEXTSURFACE_HORIZONTALPRECALCS"); //Horizontal precalcs release!
	}

	if (tsurface->verticalprecalcs) //Gotten horizontal precalcs?
	{
		freez((void **)&tsurface->verticalprecalcs,tsurface->verticalprecalcssize,"TEXTSURFACE_VERTICALPRECALCS"); //Horizontal precalcs release!
	}
	if (tsurface->lock) //Valid lock?
	{
		SDL_DestroySemaphore(tsurface->lock); //Release the semaphore!
	}
	changedealloc(tsurface, sizeof(*tsurface), getdefaultdealloc()); //Change the deallocation function back to it's default!
	//We're always allowed to release the container.
	freez((void **)ptr, sizeof(GPU_TEXTSURFACE), "GPU_TEXTSURFACE");
}

GPU_TEXTSURFACE *alloc_GPUtext()
{
	GPU_TEXTSURFACE *surface = (GPU_TEXTSURFACE *)zalloc(sizeof(GPU_TEXTSURFACE),"GPU_TEXTSURFACE",NULL); //Create an empty initialised surface!
	if (!surface) //Failed to allocate?
	{
		return NULL; //Failed to allocate!
	}
	//We don't need a screen, because we plot straight to the destination surface (is way faster than blitting)!

	surface->lock = SDL_CreateSemaphore(1); //Create our lock for when we are used!

	if (reversedinit) //Initialising?
	{
		reversedinit = 0; //Not anymore: we're generating values!
		uint_32 b;
		for (b=0;b<sizeof(int10_font_08_reversed);b++) //Precalc all reversed values!
		{
			int10_font_08_reversed[b] = reverse8(int10_font_08[b]); //Reverse it into our own ROM for fast rendering!
		}
	}

	if (!changedealloc(surface, sizeof(*surface), &freeTextSurfacePtr)) //We're changing the default dealloc function for our override!
	{
		if (surface->lock) //Lockable?
		{
			SDL_DestroySemaphore(surface->lock); //Release the semaphore!
		}
		freez((void **)&surface,sizeof(GPU_TEXTSURFACE),"GPU_TEXTSURFACE"); //Release us again!
		return NULL; //Can't change registry for 'releasing the surface container' handler!
	}

	return surface; //Give the allocated surface!
}

void free_GPUtext(GPU_TEXTSURFACE **surface)
{
	if (allcleared) return; //Abort when all is cleared!
	if (!surface) return; //Still allocated or not!
	if (!*surface) return; //Still allocated or not!
	freez((void **)surface,sizeof(GPU_TEXTSURFACE),"GPU_TEXTSURFACE"); //Release the memory, if possible!
	if (*surface) //Still allocated?
	{
		dolog("zalloc","GPU_TextSurface still allocated?");
	}
}

OPTINLINE void GPU_text_updateres(word xres, word yres) //Update resultion of the screen for supported devices!
{
#ifdef ADAPTIVETEXT
	if ((!xres) || (!yres)) //Invalid?
	{
		return; //Ignore invalid values!
	}
	render_xfactor = (float)((double)PSP_SCREEN_COLUMNS/(double)xres); //X factor!
	render_yfactor = (float)((double)PSP_SCREEN_ROWS /(double)yres); //Y factor!
	if (render_yfactor > render_xfactor)
	{
		render_xfactor = render_yfactor; //Take the lesser resolution!
	}
	else
	{
		render_yfactor = render_xfactor; //Take the lesser resolution!
	}
	render_xfactorreverse = 1.0f/render_xfactor; //Reversed!
	render_yfactorreverse = 1.0f/render_yfactor; //Reversed!
	//We're ready to be used!
#endif
}

void GPU_precalctextrenderer(void *surface) //Precalculate all that needs to be precalculated for text surfaces!
{
	if (unlikely(allcleared)) return; //Abort when all is cleared!
	if (__HW_DISABLED) return; //Disabled!
	//Don't check the surface: this is already done by the renderer itself!
	//if (!memprotect(surface,sizeof(GPU_TEXTSURFACE),"GPU_TEXTSURFACE")) return; //Abort without surface!
	if (!rendersurface) return; //No rendering surface used yet?
	INLINEREGISTER word x,y;
	int fx=0, fy=0, sx=0, sy=0; //Used when rendering on the screen!
#ifdef ADAPTIVETEXT
	float relx=0.0, rely=0.0; //Relative X/Y position to use for updating the current pixel!
#endif
	GPU_TEXTSURFACE *tsurface = (GPU_TEXTSURFACE *)surface; //Convert!
	uint_32 horizontalprecalcssize, verticalprecalcssize;

	horizontalprecalcssize = (MAX((uint_32)((GPU_TEXTPIXELSX+1)*render_xfactorreverse),(rendersurface->sdllayer->w+1))<<2); //Horizontal size!
	verticalprecalcssize = (MAX((uint_32)((GPU_TEXTPIXELSY+1)*render_yfactorreverse),(rendersurface->sdllayer->h+1))<<2); //Vertical size!

	if (((((tsurface->xdelta?TEXT_xdelta:0)==tsurface->curXDELTA)) || ((tsurface->ydelta?TEXT_ydelta:0)==tsurface->curYDELTA)) //Delta OK?
		#ifdef ADAPTIVETEXT
		&& ((tsurface->cur_render_xfactor==(float)render_xfactor) && (tsurface->cur_render_yfactor==(float)render_yfactor)) //X/Y factor to apply OK?
		#endif
		&& (tsurface->horizontalprecalcssize==horizontalprecalcssize) //Enough horizontal timings?
		&& (tsurface->verticalprecalcssize==verticalprecalcssize) //Enough vertical timings?
		&& tsurface->precalcsready //Precalcs ready?
		) //Already up-to-date precalcs?
	{
		return; //Up-to-date: don't recalculate the precalcs!
	}

	//Update delta values!
	tsurface->curXDELTA = tsurface->xdelta?TEXT_xdelta:0;
	tsurface->curYDELTA = tsurface->ydelta?TEXT_ydelta:0;

	#ifdef ADAPTIVETEXT
	//Update factors used when rendering!
	tsurface->cur_render_xfactor = (float)render_xfactor;
	tsurface->cur_render_yfactor = (float)render_yfactor; //X/Y factor to apply OK?
	#endif

	if (tsurface->horizontalprecalcs) //Gotten horizontal precalcs?
	{
		freez((void **)&tsurface->horizontalprecalcs,tsurface->horizontalprecalcssize,"TEXTSURFACE_HORIZONTALPRECALCS"); //Horizontal precalcs release!
	}

	if (tsurface->verticalprecalcs) //Gotten vertical precalcs?
	{
		freez((void **)&tsurface->verticalprecalcs,tsurface->verticalprecalcssize,"TEXTSURFACE_VERTICALPRECALCS"); //Horizontal precalcs release!
	}

	tsurface->horizontalprecalcssize = horizontalprecalcssize; //Horizontal size!
	tsurface->horizontalprecalcsentries = (horizontalprecalcssize>>2); //Horizontal size, in entries!
	tsurface->verticalprecalcssize = verticalprecalcssize; //Vertical size!
	tsurface->verticalprecalcsentries = (verticalprecalcssize>>2); //Vertical size, in entries!

	tsurface->horizontalprecalcs = zalloc(tsurface->horizontalprecalcssize,"TEXTSURFACE_HORIZONTALPRECALCS",NULL); //Lockless precalcs!
	tsurface->verticalprecalcs = zalloc(tsurface->verticalprecalcssize,"TEXTSURFACE_VERTICALPRECALCS",NULL); //Lockless precalcs!

	memset(tsurface->horizontalprecalcs,0xFF,tsurface->horizontalprecalcssize); //Init to invalid location!
	memset(tsurface->verticalprecalcs,0xFF,tsurface->verticalprecalcssize); //Init to invalid location!

	//Now, precalculate all required data for the surface to render it's locations!
	x = y = sx = sy = 0; //Init coordinates!
#ifdef ADAPTIVETEXT
	relx = rely = 0.0f; //Init screen coordinate plotter!
#endif
	if (unlikely(check_surface(rendersurface))) //Valid to render to?
	{
		for (;;) //Process all x coordinates!
		{
			fx = sx; //x converted to destination factor!
			if (tsurface->xdelta) fx += TEXT_xdelta; //Apply delta position to the output pixel!
			if ((fx>=0) && (fx<tsurface->horizontalprecalcsentries) && (x<GPU_TEXTPIXELSX)) //Valid pixel to render the surface?
			{
				tsurface->horizontalprecalcs[fx] = x; //Save the outgoing pixel location mapping on the screen!
			}

			#ifdef ADAPTIVETEXT
			relx += render_xfactor; //We've rendered a pixel!
			#endif
			++sx; //Screen pixel rendered!
			#ifdef ADAPTIVETEXT
			for (;relx>=1.0f;) //Expired?
			#endif
			{
			#ifdef ADAPTIVETEXT
				relx -= 1.0f; //Rest!
			#endif
				//Else, We're transparent, do don't plot!
				if (unlikely(++x==GPU_TEXTPIXELSX)) //End of row reached?
				{
					goto startprocessy; //Stop processing horizontal coordinates!
				}
			}
		}

		startprocessy:
		for (;;) //Process all y coordinates!
		{
			fy = sy; //y converterd to destination factor!
			if (tsurface->ydelta) fy += TEXT_ydelta; //Apply delta position to the output pixel!
			if ((fy>=0) && (fy<tsurface->verticalprecalcsentries) && (y<GPU_TEXTPIXELSY)) //Valid pixel to render the surface?
			{
				tsurface->verticalprecalcs[fy] = y; //Save the outgoing pixel location mapping on the screen!
			}
			#ifdef ADAPTIVETEXT
			rely += render_yfactor; //We've rendered a row!
			#endif
			++sy; //Screen row rendered!
			#ifdef ADAPTIVETEXT
			for (;rely>=1.0;) //Expired?
			#endif
			{
			#ifdef ADAPTIVETEXT
				rely -= 1.0f; //Rest!
			#endif
				if (unlikely(++y==GPU_TEXTPIXELSY)) //End of lines reached?
				{
					goto finishprocess; //Stop processing horizontal coordinates!
				}
			}
		}
		finishprocess:
		tsurface->precalcsready = 1; //We're ready after this!
	}
}

uint_64 GPU_textrenderer(void *surface) //Run the text rendering on rendersurface!
{
	if (unlikely(allcleared)) return 0; //Abort when all is cleared!
	uint_32 *renderpixel;
	byte *xfont, *xchar;
	if (__HW_DISABLED) return 0; //Disabled!
	if (!memprotect(surface,sizeof(GPU_TEXTSURFACE),"GPU_TEXTSURFACE")) return 0; //Abort without surface!
	if (!rendersurface) return 0; //No rendering surface used yet?
	uint_32 color;
	INLINEREGISTER int x,y;
	INLINEREGISTER uint_32 notbackground; //We're a pixel to render, 32-bits for each 32 pixels!
	INLINEREGISTER byte isnottransparent=0; //Are we not a transparent pixel(drawable)?
	byte curchar=0; //The current character loaded font row!
	int sx=0, sy=0; //Used when rendering on the screen!
	GPU_TEXTSURFACE *tsurface = (GPU_TEXTSURFACE *)surface; //Convert!
	INLINEREGISTER uint_32 prevs, curs; //Current and previous pixel to compare!

	GPU_precalctextrenderer(surface); //Update our precalcs, when needed only!

	if (unlikely(tsurface->flags&TEXTSURFACE_FLAG_DIRTY)) //Redraw when dirty only?
	{
		WaitSem(tsurface->lock);

		//First phase: get all pixels font/background status, by walking through the text!
		x = y = 0; //Init coordinates!
		xfont = &tsurface->fontpixels[0]; //The font pixels to use! as output!
		xchar = &tsurface->text[0][0]; //The font pixels to use! as output!

		do //Process all rows!
		{
			curchar = getcharxy_8(*xchar,y&7); //Get the current row to process!
			//Process the entire row!
			*xfont++ = (curchar&1); //Current pixel!
			curchar >>= 1; //Shift next in!
			*xfont++ = (curchar & 1); //Current pixel!
			curchar >>= 1; //Shift next in!
			*xfont++ = (curchar & 1); //Current pixel!
			curchar >>= 1; //Shift next in!
			*xfont++ = (curchar & 1); //Current pixel!
			curchar >>= 1; //Shift next in!
			*xfont++ = (curchar & 1); //Current pixel!
			curchar >>= 1; //Shift next in!
			*xfont++ = (curchar & 1); //Current pixel!
			curchar >>= 1; //Shift next in!
			*xfont++ = (curchar & 1); //Current pixel!
			curchar >>= 1; //Shift next in!
			*xfont++ = (curchar & 1); //Current pixel!
			//Move to the next horizontal character!
			++xchar; //Next character!
			if (unlikely(++x == GPU_TEXTSURFACE_WIDTH)) //End of row reached?
			{
				x = 0; //Reset horizontal coordinate!
				++y; //Goto Next row!
				xfont = GPU_textget_pixelrowptr(tsurface,y); //Next row loaded!
				xchar = &tsurface->text[y>>3][0]; //Next row loaded!
			}
		} while (likely(y != GPU_TEXTPIXELSY)); //Stop searching now!	

		//Second phase: update dirty pixels with their correct font/border/transparent color!
		x = y = 0; //Init coordinates!
		do //Process all rows!
		{
			updateDirty(tsurface,x,y); //Update dirty if needed!
			if (unlikely(tsurface->notdirty[(y<<9)|x]!=TRANSPARENTPIXEL)) //Used pixel to render?
			{
				tsurface->notbackground[(y<<4)|(x>>5)] |= (1<<(x&0x1F)); //We're set!
			}
			else //Transparent pixel?
			{
				tsurface->notbackground[(y<<4)|(x>>5)] &= ~(1<<(x&0x1F)); //We're not set: we're transparent!
			}
			if (unlikely(++x==GPU_TEXTPIXELSX)) //End of row reached?
			{
				x = 0; //Reset horizontal coordinate!
				++y; //Goto Next row!
			}
		} while (likely(y!=GPU_TEXTPIXELSY)); //Stop searching now!	
		tsurface->flags &= ~TEXTSURFACE_FLAG_DIRTY; //Clear dirty flag!
		PostSem(tsurface->lock); //We're finished with the surface!
	}

	x = y = sx = sy = 0; //Init coordinates!
	if (unlikely(check_surface(rendersurface)) && tsurface->precalcsready) //Valid to render to?
	{
		renderpixel = &tsurface->notdirty[0]; //Start with the first pixel in our buffer!
		notbackground = tsurface->notbackground[0]; //Are we not the background?
		if (tsurface->horizontalprecalcs[0]!=~0) //Valid first part?
		{
			isnottransparent = (notbackground&1); //Are we a transparent pixel?
		}
		else
		{
			isnottransparent = notbackground = 0; //Init to transparant!
		}
		if (unlikely(isnottransparent)) //Color needed?
		{
			color = *renderpixel; //Init color to draw!
		}
		if (unlikely(sx >= rendersurface->sdllayer->w)) return 0; //Invalid column!
		uint_32 *renderpixels = (uint_32 *)rendersurface->sdllayer->pixels; //The pixels to draw to!
		uint_32 *currentrow = &renderpixels[ ( sy * get_pixelrow_pitch(rendersurface) )]; //The pixel row!
		for (;;) //Process all rows!
		{
			if (unlikely(isnottransparent)) //The pixel to plot, if any! Ignore transparent pixels!
			{
				if (unlikely(sx >= rendersurface->sdllayer->w)) goto nextpixel; //Invalid column!
				if (unlikely(sy >= rendersurface->sdllayer->h)) goto nextpixel; //Invalid row!
				if (unlikely(currentrow[sx]!=color)) //Different?
				{
					rendersurface->flags |= SDL_FLAG_DIRTY; //Mark as dirty!
					currentrow[sx] = color;
				}
			}
			nextpixel:

			prevs = tsurface->horizontalprecalcs[sx++]; //Previous SX result! Increase, because a pixel has been rendered!
			if (unlikely(sx>=tsurface->horizontalprecalcsentries)) //End of row block reached? Prevent invalid rows by immediately starting the next when it's occurring!
			{
				goto loadnextrow;
			}
			curs = tsurface->horizontalprecalcs[sx]; //Current SX result!
			if (unlikely(prevs!=curs)) //Coordinate changed?
			{
				if (unlikely(prevs!=~0)) //We were active?
					if (unlikely(curs==~0)) //Finished a row(end of specified area) now?
						goto loadnextrow; //Load the next row!
				if (likely(sx<tsurface->horizontalprecalcsentries)) //End of row not reached?
				{
					if (likely(curs==~0)) //Invalid?
					{
						notbackground = 0; //We're background only!
					}
					else //Valid horizontal location?
					{
						++renderpixel; //We've rendered a pixel!
						x = curs; //Load the new y coordinate to use!
						if (likely((curs&0x1F)!=0)) //To not reload the foreground mask?
						{
							notbackground >>= 1; //Take the next pixel from the background mask!
						}
						else
						{
							notbackground = tsurface->notbackground[(y<<4)|(curs>>5)]; //Load the next background mask!
						}
					}
				}
				else //Forced next row?
				{
					loadnextrow: //Load the next row to render!
					notbackground = 0; //Default to background always!
					sx = 0; //Reset horizontal coordinate!
					x = tsurface->horizontalprecalcs[sx]; //Load the new x coordinate to use!
					prevs = tsurface->verticalprecalcs[sy]; //Previous SY result!
					++sy; //Screen row rendered!
					currentrow = &renderpixels[ ( sy * get_pixelrow_pitch(rendersurface) )]; //The new pixel row!
					if (unlikely(sy>=tsurface->verticalprecalcsentries)) break; //Finished!
					curs = tsurface->verticalprecalcs[sy]; //Current SY result!
					if (unlikely((prevs!=~0) && (curs==~0))) //Finished a screen(end of specified area)?
					{
						break; //Finished the specified area!
					}
					if (likely(curs!=~0)) //Valid?
					{
						y = curs; //Load the new y coordinate to use!
						renderpixel = &tsurface->notdirty[y<<9]; //Start with the first pixel in our (new) row!
						notbackground = tsurface->notbackground[y<<4]; //Load the new row's first foreground mask!
						if (unlikely(x==~0)) //Starting out invalid?
						{
							notbackground = 0; //We're background to start with!
						}
					}
					else //Invalid vertical location?
					{
						notbackground = 0; //We're background!
					}
				}
				if (unlikely(isnottransparent = (notbackground&1))) //To render us?
				{
					color = *renderpixel; //Apply the new pixel to render!
				}
			}
		} //Stop searching now!
	}

	return 0; //Ignore processing time!
}

int GPU_textgetxy(GPU_TEXTSURFACE *surface,int x, int y, byte *character, uint_32 *font, uint_32 *border) //Read a character+attribute!
{
	if (allcleared) return 0; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(GPU_TEXTSURFACE), "GPU_TEXTSURFACE")) return 0; //Abort without surface!
	if (y >= GPU_TEXTSURFACE_HEIGHT) return 0; //Out of bounds?
	if (x>=GPU_TEXTSURFACE_WIDTH) return 0; //Out of bounds?
	*character = surface->text[y][x];
	*font = surface->font[y][x];
	*border = surface->border[y][x];
	return 1; //OK!
}

byte GPU_startClickable(GPU_TEXTSURFACE *surface, word x, word y); //Internal: start clickable character prototype!
void GPU_stopClickableXY(GPU_TEXTSURFACE *surface, word x, word y); //Internal: stop clickable character prototype!

byte GPU_textsetxyclickable(GPU_TEXTSURFACE *surface, int x, int y, byte character, uint_32 font, uint_32 border, byte ignoreempty) //Set x/y coordinates for clickable character! Result is bit value of SETXYCLICKED_*
{
	if (allcleared) return 0; //Abort when all is cleared!
	byte result=0;
	if (!memprotect(surface, sizeof(GPU_TEXTSURFACE), "GPU_TEXTSURFACE")) return 0; //Abort without surface!
	if (y >= GPU_TEXTSURFACE_HEIGHT) return 0; //Out of bounds?
	if (x >= GPU_TEXTSURFACE_WIDTH) return 0; //Out of bounds?
	byte oldtext = surface->text[y][x];
	uint_32 oldfont = surface->font[y][x];
	uint_32 oldborder = surface->border[y][x];
	surface->text[y][x] = character;
	surface->font[y][x] = font;
	surface->border[y][x] = border;
	if ((!ignoreempty) || ((character!=(char)0) && (character!=' '))) //Not an empty character?
	{
		result = GPU_startClickable(surface, x, y) ? (SETXYCLICKED_OK | SETXYCLICKED_CLICKED) : SETXYCLICKED_OK; //We're starting to be clickable if not yet clickable! Give 3 for clicked and 1 for normal success without click!
	}
	uint_32 change;
	character ^= oldtext;
	font ^= oldfont;
	border ^= oldborder;
	change = character;
	change |= font;
	change |= border;
	if (change) surface->flags |= TEXTSURFACE_FLAG_DIRTY; //Mark us as dirty when needed!
	return result; //OK with error condition!
}

int GPU_textsetxy(GPU_TEXTSURFACE *surface,int x, int y, byte character, uint_32 font, uint_32 border) //Write a character+attribute!
{
	if (allcleared) return 0; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(GPU_TEXTSURFACE), NULL)) return 0; //Abort without surface!
	if (y>=GPU_TEXTSURFACE_HEIGHT) return 0; //Out of bounds?
	if (x>=GPU_TEXTSURFACE_WIDTH) return 0; //Out of bounds?
	byte oldtext = surface->text[y][x];
	uint_32 oldfont = surface->font[y][x];
	uint_32 oldborder = surface->border[y][x];
	surface->text[y][x] = character;
	surface->font[y][x] = font;
	surface->border[y][x] = border;
	GPU_stopClickableXY(surface,x,y); //We're stopping being clickable: we're a normal character from now on!
	uint_32 change;
	character ^= oldtext;
	font ^= oldfont;
	border ^= oldborder;
	change = character;
	change |= font;
	change |= border;
	if (change) surface->flags |= TEXTSURFACE_FLAG_DIRTY; //Mark us as dirty when needed!
	return 1; //OK!
}

int GPU_textsetxyfont(GPU_TEXTSURFACE *surface, int x, int y, uint_32 font, uint_32 border) //Write a attribute only!
{
	if (allcleared) return 0; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(GPU_TEXTSURFACE), NULL)) return 0; //Abort without surface!
	if (y >= GPU_TEXTSURFACE_HEIGHT) return 0; //Out of bounds?
	if (x >= GPU_TEXTSURFACE_WIDTH) return 0; //Out of bounds?
	uint_32 oldfont = surface->font[y][x];
	uint_32 oldborder = surface->border[y][x];
	surface->font[y][x] = font;
	surface->border[y][x] = border;
	uint_32 change;
	font ^= oldfont;
	border ^= oldborder;
	change = font;
	change |= border;
	if (change) surface->flags |= TEXTSURFACE_FLAG_DIRTY; //Mark us as dirty when needed!
	return 1; //OK!
}

void GPU_textclearrow(GPU_TEXTSURFACE *surface, int y)
{
	if (allcleared) return; //Abort when all is cleared!
	int x=0;
	for (;;)
	{
		GPU_textsetxy(surface,x,y,0,0,0); //Clear the row fully!
		if (++x>=GPU_TEXTSURFACE_WIDTH) return; //Done!
	}
}

void GPU_textclearcurrentrownext(GPU_TEXTSURFACE *surface) //For clearing the rest of the current row!
{
	if (allcleared) return; //Abort when all is cleared!
	int x = surface->x; //Start at the current coordinates!
	for (;;)
	{
		GPU_textsetxy(surface, x, surface->y, 0, 0, 0); //Clear the row fully!
		if (++x >= GPU_TEXTSURFACE_WIDTH) return; //Done!
	}
}

void GPU_textclearscreen(GPU_TEXTSURFACE *surface)
{
	if (allcleared) return; //Abort when all is cleared!
	int y=0;
	for (;;)
	{
		GPU_textclearrow(surface,y); //Clear all rows!
		if (++y>=GPU_TEXTSURFACE_HEIGHT) return; //Done!
	}
}

OPTINLINE void GPU_textclipXY(int *curx, int *cury)
{
	while (*curx >= GPU_TEXTSURFACE_WIDTH) //Overflow?
	{
		++*cury; //Next row!
		*curx -= GPU_TEXTSURFACE_WIDTH; //Decrease columns for every row size!
	}
	while (*cury >= GPU_TEXTSURFACE_WIDTH) //Overflow?
	{
		*cury -= GPU_TEXTSURFACE_HEIGHT; //Decrease columns for every row size!
	}
}

void GPU_textprintf(GPU_TEXTSURFACE *surface, uint_32 font, uint_32 border, char *text, ...)
{
	if (allcleared) return; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(GPU_TEXTSURFACE), "GPU_TEXTSURFACE")) return; //Abort without surface!
	char msg[256];
	cleardata(&msg[0],sizeof(msg)); //Init!

	va_list args; //Going to contain the list!
	va_start (args, text); //Start list!
	vsprintf (msg, text, args); //Compile list!

	int curx=surface->x; //Init x!
	int cury=surface->y; //init y!
	int startx=curx; //Save a backup of the start location to jump back to!
	int i;
	for (i=0; i<(int)strlen(msg); i++) //Process text!
	{
		GPU_textclipXY(&curx,&cury); //Clip!
		if (msg[i]=='\t') //Jump back to horizontal start position?
		{
			curx = startx; //Jump back to the horizontal start position!
			GPU_textclipXY(&curx,&cury); //Clip!
		}
		else if ((msg[i]=='\r' && !USESLASHN) || (msg[i]=='\n' && USESLASHN)) //LF? If use \n, \n uses linefeed too, else just newline.
		{
			curx = 0; //Move to the left!
		}
		if (msg[i]=='\n') //CR?
		{
			++cury; //Next Y!
			GPU_textclipXY(&curx,&cury); //Clip!
		}
		else if ((msg[i] != '\r') && (msg[i] != '\t')) //Never display \r or \t!
		{
			GPU_textsetxy(surface,curx,cury,(byte)msg[i],font,border); //Write the character to our screen!
			++curx; //Next character!
		}
	}
	GPU_textclipXY(&curx,&cury); //Clip!
	surface->x = curx; //Update x!
	surface->y = cury; //Update y!
}

byte GPU_textprintfclickable(GPU_TEXTSURFACE *surface, uint_32 font, uint_32 border, byte ignoreempty, char *text, ...)
{
	if (allcleared) return 0; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(GPU_TEXTSURFACE), "GPU_TEXTSURFACE")) return 0; //Abort without surface!
	char msg[256];
	cleardata(&msg[0], sizeof(msg)); //Init!

	va_list args; //Going to contain the list!
	va_start(args, text); //Start list!
	vsprintf(msg, text, args); //Compile list!

	int curx = surface->x; //Init x!
	int cury = surface->y; //init y!
	int startx = curx; //Save a backup of the start location to jump back to!
	int i;
	byte result = SETXYCLICKED_OK; //Default: we're OK!
	byte setstatus; //Status when setting!
	for (i = 0; i<(int)strlen(msg); i++) //Process text!
	{
		GPU_textclipXY(&curx,&cury); //Clip!
		if (msg[i]=='\t') //Jump back to horizontal start position?
		{
			curx = startx; //Jump back to the horizontal start position!
			GPU_textclipXY(&curx,&cury); //Clip!
		}
		else if ((msg[i] == '\r' && !USESLASHN) || (msg[i] == '\n' && USESLASHN)) //LF? If use \n, \n uses linefeed too, else just newline.
		{
			curx = 0; //Move to the left!
		}
		if (msg[i] == '\n') //CR?
		{
			++cury; //Next Y!
			GPU_textclipXY(&curx,&cury); //Clip!
		}
		else if ((msg[i] != '\r') && (msg[i]!='\t')) //Never display \r or \t!
		{
			setstatus = GPU_textsetxyclickable(surface, curx, cury, (byte)msg[i], font, border,ignoreempty); //Write the character to our screen!
			if (!(setstatus&SETXYCLICKED_OK)) //Invalid character location or unknown status value?
			{
				result &= ~SETXYCLICKED_OK; //Error out: we have one or more invalid writes!
			}

			if (setstatus&SETXYCLICKED_CLICKED) //Are we clicked?
			{
				result |= SETXYCLICKED_CLICKED; //We're clicked!
			}
			++curx; //Next character!
		}
	}
	GPU_textclipXY(&curx,&cury); //Clip!
	surface->x = curx; //Update x!
	surface->y = cury; //Update y!
	return result; //Give the result!
}

void GPU_textgotoxy(GPU_TEXTSURFACE *surface,int x, int y) //Goto coordinates!
{
	if (allcleared) return; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(GPU_TEXTSURFACE), NULL)) return; //Abort without surface!
	int curx = x;
	int cury = y;
	GPU_textclipXY(&curx,&cury); //Clip!
	surface->x = curx; //Real x!
	surface->y = cury; //Real y!
}

void GPU_enableDelta(GPU_TEXTSURFACE *surface, byte xdelta, byte ydelta) //Enable delta coordinates on the x/y axis!
{
	if (allcleared) return; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(GPU_TEXTSURFACE), "GPU_TEXTSURFACE")) return; //Abort without surface!
	surface->xdelta = xdelta; //Enable x delta?
	surface->ydelta = ydelta; //Enable y delta?
}

void GPU_text_updatedelta(SDL_Surface *surface)
{
	if (allcleared) return; //Abort when all is cleared!
	if (!surface) //Invalid surface!
	{
		TEXT_xdelta = TEXT_ydelta = 0; //No delta!
		return; //Invalid surface: no delta used!
	}
	GPU_text_updateres(surface->w,surface->h); //Update our resolution if needed for this device!
	sword xdelta, ydelta;
	xdelta = surface->w; //Current resolution!
	ydelta = surface->h; //Current resolution!
	xdelta -= (sword)(GPU_TEXTPIXELSX*render_xfactorreverse);
	ydelta -= (sword)(GPU_TEXTPIXELSY*render_yfactorreverse); //Calculate delta!
	TEXT_xdelta = xdelta; //Horizontal delta!
	TEXT_ydelta = ydelta; //Vertical delta!
}

void GPU_text_locksurface(GPU_TEXTSURFACE *surface) //Lock a surface for usage!
{
	if (allcleared) return; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(*surface), "GPU_TEXTSURFACE")) return; //Invalid surface!
	if (!surface->lock) return; //no lock?
	WaitSem(surface->lock) //Wait for us to be available and locked!
}

void GPU_text_releasesurface(GPU_TEXTSURFACE *surface) //Unlock a surface when done with it!
{
	if (allcleared) return; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(*surface), NULL)) return; //Invalid surface!
	if (!surface->lock) return; //no lock?
	PostSem(surface->lock) //Release our lock: we're done!
}

byte GPU_textbuttondown(GPU_TEXTSURFACE *surface, byte finger, word x, word y) //We've been clicked at these coordinates!
{
	if (allcleared) return 0; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(*surface), "GPU_TEXTSURFACE")) return 0; //Invalid surface!
	word x1, y1;
	x1 = 0;
	y1 = 0;
	if (surface->xdelta) x1 += TEXT_xdelta; //Apply delta position to the output pixel!
	if (surface->ydelta) y1 += TEXT_ydelta; //Apply delta position to the output pixel!

	//Now x1,y1 is the start of the surface!
	if (x >= x1) //Within x range?
	{
		if (y >= y1) //Within y range?
		{
			x -= x1; //X coordinate within the surface!
			y -= y1;  //Y coordinate within the surface!
			x = (word)((float)x*render_xfactor); //Convert to our destination size!
			y = (word)((float)y*render_yfactor); //Convert to our destination size!
			if (x < GPU_TEXTPIXELSX) //Within horizontal range?
			{
				if (y < GPU_TEXTPIXELSY) //Within vertical range?
				{
					x >>= 3; //X character within the surface!
					y >>= 3; //Y character within the surface!
					if (surface->clickable[y][x] & CLICKABLE_CLICKABLE) //Is this a clickable character?
					{
						surface->clickable[y][x] |= CLICKABLE_BUTTONDOWN; //Set button down flag!
						surface->clickablefinger[y][x] = finger; //What finger?
						return 1; //We're handled!
					}
				}
			}
		}
	}
	return 0; //We're not handled!
}

void GPU_textbuttonup(GPU_TEXTSURFACE *surface, byte finger, word x, word y) //We've been released at these coordinates!
{
	if (allcleared) return; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(*surface), "GPU_TEXTSURFACE")) return; //Invalid surface!

	word sx, sy;
	for (sx = 0;sx < GPU_TEXTSURFACE_WIDTH;)
	{
		for (sy = 0;sy < GPU_TEXTSURFACE_HEIGHT;)
		{
			byte clickable;
			clickable = surface->clickable[sy][sx]; //Load clickable info on the current character!
			if (clickable & CLICKABLE_CLICKABLE) //Clickable character?
			{
				if (clickable&CLICKABLE_BUTTONDOWN) //We're pressed?
				{
					if (surface->clickablefinger[sy][sx]==finger) //Same finger?
					{
						clickable &= ~CLICKABLE_BUTTONDOWN; //Release hold!
						clickable |= CLICKABLE_CLICKED; //We've been clicked!
						surface->clickable[sy][sx] = clickable; //Update clicked information!
					}
				}
			}
			++sy;
		}
		++sx;
	}
}

byte GPU_startClickable(GPU_TEXTSURFACE *surface, word x, word y) //Internal: start clickable character!
{
	if (allcleared) return 0; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(*surface), "GPU_TEXTSURFACE")) return 0; //Invalid surface!
	byte result = 0;
	if (!(surface->clickable[y][x] & CLICKABLE_CLICKABLE)) //We're not clickable yet?
	{
		surface->clickable[y][x] = CLICKABLE_CLICKABLE; //Enable clickable and start fresh!
	}
	else
	{
		if (surface->clickable[y][x] & CLICKABLE_CLICKED) //Are we clicked?
		{
			surface->clickable[y][x] &= ~CLICKABLE_CLICKED; //We're processing the click now!
			result = 1; //We're clicked!
		}
	}
	return result; //Give if we're clicked or not!
}

byte GPU_isclicked(GPU_TEXTSURFACE *surface, word x, word y) //Are we clicked?
{
	if (allcleared) return 0; //Abort when all is cleared!
	byte result;
	if (!memprotect(surface, sizeof(*surface), "GPU_TEXTSURFACE")) return 0; //Invalid surface!
	result = (surface->clickable[y][x]&(CLICKABLE_CLICKABLE|CLICKABLE_CLICKED))== (CLICKABLE_CLICKABLE | CLICKABLE_CLICKED); //Give if we're clickable and clicked!
	return result; //Give the result if we're clicked!
}

byte GPU_ispressed(GPU_TEXTSURFACE *surface, word x, word y) //Are we pressed?
{
	if (allcleared) return 0; //Abort when all is cleared!
	byte result;
	if (!memprotect(surface, sizeof(*surface), "GPU_TEXTSURFACE")) return 0; //Invalid surface!
	result = (surface->clickable[y][x]&(CLICKABLE_CLICKABLE|CLICKABLE_BUTTONDOWN))== (CLICKABLE_CLICKABLE | CLICKABLE_BUTTONDOWN); //Give if we're clickable and clicked!
	return result; //Give the result if we're clicked!
}

void GPU_stopClickableXY(GPU_TEXTSURFACE *surface, word x, word y)
{
	if (allcleared) return; //Abort when all is cleared!
	if (!memprotect(surface, sizeof(*surface), NULL)) return; //Invalid surface!
	surface->clickable[y][x] = 0; //Destroy any click information! We're a normal character again!
}
