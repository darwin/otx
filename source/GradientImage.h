/*
	GradientImage.h

	This file is in the public domain.
*/

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

-(void)setStartColor: (NSColor*)startColor
		 andEndColor: (NSColor*)endColor;

@end
