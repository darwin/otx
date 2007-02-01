/*
	GradientImage.m

	This file is in the public domain.
*/

#import "GradientImage.h"

static void
Evaluate(
	void*			inData,
	const float*	inValue,
	float*			outValue);

static void
Evaluate(
	void*			inData,
	const float*	inValue,
	float*			outValue)
{
	if (!inData || !inValue)
	{
		outValue[0] = outValue[1] = outValue[2] = outValue[3] = 1.0;
		return;
	}

	GradientData	data	= *(GradientData*)inData;

	outValue[0]	= INTERPOLATE(data.r1, data.r2, *inValue);
	outValue[1]	= INTERPOLATE(data.g1, data.g2, *inValue);
	outValue[2]	= INTERPOLATE(data.b1, data.b2, *inValue);
	outValue[3]	= INTERPOLATE(data.a1, data.a2, *inValue);
}

@implementation GradientImage

//	initWithSize:
// ----------------------------------------------------------------------------

- (id)initWithSize: (NSSize)aSize
{
    if (!(self = [super initWithSize: aSize]))
        return nil;

    return self;
}

//	dealloc
// ----------------------------------------------------------------------------

- (void)dealloc
{
	if (mGradientFunc)
		CGFunctionRelease(mGradientFunc);

	[super dealloc];
}

//	setStartColor:andEndColor:
// ----------------------------------------------------------------------------

-(void)setStartColor: (NSColor*)startColor
		 andEndColor: (NSColor*)endColor
{
	if (!startColor || !endColor)
	{
		fprintf(stderr, "otx: [GradientView setStartColor:andEndColor:] "
			"nil values\n");
		return;
	}

	[startColor getRed: &mData.r1 green: &mData.g1
		blue: &mData.b1 alpha: &mData.a1];
	[endColor getRed: &mData.r2 green: &mData.g2
		blue: &mData.b2 alpha: &mData.a2];

	CGFunctionCallbacks	cgCallback = {0 , &Evaluate, nil};

	if (mGradientFunc)
		CGFunctionRelease(mGradientFunc);

	mGradientFunc	= CGFunctionCreate(
		&mData, 1, gInputRange, 4, gOutputRanges, &cgCallback);

	[self lockFocus];

	CGPoint	startPoint	= CGPointMake(0.0, [self size].height);
	CGPoint	endPoint	= CGPointMake(0.0, 0.0);

	CGContextRef	savedContext	=
		(CGContextRef)[[NSGraphicsContext currentContext] graphicsPort];

	CGContextSaveGState(savedContext);

	CGColorSpaceRef colorSpace	=
		CGColorSpaceCreateWithName(kCGColorSpaceGenericRGB);
	CGShadingRef	shading	= CGShadingCreateAxial(
		colorSpace, startPoint, endPoint, mGradientFunc, false, false);

	CGContextDrawShading(savedContext, shading);
	  
	[self unlockFocus];

	CGShadingRelease(shading);
	CGColorSpaceRelease(colorSpace);
	CGContextRestoreGState(savedContext);
}

@end
