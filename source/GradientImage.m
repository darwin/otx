/*
	GradientImage.m

	An image that gradates from one color to another vertically. This is a
	severely limited adaptation of Chad Weider's CTGradient class:
	http://blog.oofn.net/2006/01/15/gradients-in-cocoa/
	Consider using CTGradient if you need more than just a polished metal
	window.

	This file is in the public domain.
*/

#import "GradientImage.h"

//	Evaluate
// ----------------------------------------------------------------------------

static void
Evaluate(
	void*			inData,
	const float*	inValue,
	float*			outValue)
{
	if (!outValue)
		return;

	if (!inData || !inValue)
	{	// Default to black in a fast, hackish way.
		memset(outValue, 0, sizeof(float) * 4);
		return;
	}

	GradientData	data	= *(GradientData*)inData;

	outValue[0]	= INTERPOLATE(data.r1, data.r2, *inValue);
	outValue[1]	= INTERPOLATE(data.g1, data.g2, *inValue);
	outValue[2]	= INTERPOLATE(data.b1, data.b2, *inValue);
	outValue[3]	= INTERPOLATE(data.a1, data.a2, *inValue);
}

@implementation GradientImage

//	initWithSize:data:
// ----------------------------------------------------------------------------

- (id)initWithSize: (NSSize)inSize
			  data: (GradientData*)inData
{
	if (!inData)
	{
		fprintf(stderr, "otx: [GradientView initWithSize:data:] "
			"nil data\n");
		return nil;
	}

	if ((self = [super initWithSize: inSize]))
	{
		mData	= *inData;

		CGFunctionCallbacks	cgCallback = {0 , &Evaluate, nil};

		// CGFunctionCreate() cannot fail. Nice.
		mGradientFunc	= CGFunctionCreate(
			&mData, 1, gInputRange, 4, gOutputRanges, &cgCallback);

		CGPoint	startPoint	= CGPointMake(0.0, inSize.height);
		CGPoint	endPoint	= CGPointMake(0.0, 0.0);

		[self lockFocus];

		CGContextRef	savedContext	=
			(CGContextRef)[[NSGraphicsContext currentContext] graphicsPort];

		CGContextSaveGState(savedContext);

		// CGColorSpaceCreateWithName() CAN fail.
		CGColorSpaceRef colorSpace	=
			CGColorSpaceCreateWithName(kCGColorSpaceGenericRGB);

		if (!colorSpace)
		{
			CGContextRestoreGState(savedContext);
			[self release];
			return nil;
		}

		// CGShadingCreateAxial() cannot fail.
		CGShadingRef	shading	= CGShadingCreateAxial(
			colorSpace, startPoint, endPoint, mGradientFunc, false, false);

		CGContextDrawShading(savedContext, shading);

		[self unlockFocus];

		CGShadingRelease(shading);
		CGColorSpaceRelease(colorSpace);
		CGContextRestoreGState(savedContext);
	}

	return self;
}

//	dealloc
// ----------------------------------------------------------------------------

- (void)dealloc
{
	if (mGradientFunc)
	{
		CGFunctionRelease(mGradientFunc);
		mGradientFunc	= nil;
	}

	[super dealloc];
}

@end
