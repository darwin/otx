/*
	GradientImage.h

	An image that gradates from one color to another vertically. This is a
	severely limited adaptation of Chad Weider's CTGradient class:
	http://blog.oofn.net/2006/01/15/gradients-in-cocoa/
	Consider using CTGradient if you need more than just a polished metal
	window.

	This file is in the public domain.
*/

//#define	_INSANE_OPTIMIZATION_	1

typedef struct GradientData 
{
	float	r1;
	float	g1;
	float	b1;
	float	a1;
	float	r2;
	float	g2;
	float	b2;
	float	a2;
}
GradientData;

static const float gInputRange[2]	= {0, 1};
static const float gOutputRanges[8]	= {0, 1, 0, 1, 0, 1, 0, 1};

#define INTERPOLATE(a, b, pos)	((((b) - (a)) * (pos)) + (a))

@interface GradientImage : NSImage
{
@private
	GradientData	mData;
	CGFunctionRef	mGradientFunc;
}

- (id)initWithSize: (NSSize)inSize
			color1: (NSColor*)color1
			color2: (NSColor*)color2;
//-(void)setStartColor: (NSColor*)startColor
//			endColor: (NSColor*)endColor;

@end
