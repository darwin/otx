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

//	initWithSize:color1:color2
// ----------------------------------------------------------------------------

- (id)initWithSize: (NSSize)inSize
			color1: (NSColor*)color1
			color2: (NSColor*)color2
{
	if (!color1 || !color2)
	{
		fprintf(stderr, "otx: [GradientView initWithSize:color1:color2] "
			"nil color(s)\n");
		return nil;
	}

	// I'm assuming initWithSize: calls setSize:. Is this the case?
	[color1 getRed: &mData.r1 green: &mData.g1
		blue: &mData.b1 alpha: &mData.a1];
	[color2 getRed: &mData.r2 green: &mData.g2
		blue: &mData.b2 alpha: &mData.a2];

	if (!(self = [super initWithSize: inSize]))
		return nil;

#if	_INSANE_OPTIMIZATION_
#else
	CGFunctionCallbacks	cgCallback = {0 , &Evaluate, nil};

	// CGFunctionCreate() cannot fail. Nice.
	mGradientFunc	= CGFunctionCreate(
		&mData, 1, gInputRange, 4, gOutputRanges, &cgCallback);

	[self lockFocus];

	CGPoint	startPoint	= CGPointMake(0.0, inSize.height);
	CGPoint	endPoint	= CGPointMake(0.0, 0.0);

	CGContextRef	savedContext	=
		(CGContextRef)[[NSGraphicsContext currentContext] graphicsPort];

	CGContextSaveGState(savedContext);

	// CGColorSpaceCreateWithName() CAN fail.
	CGColorSpaceRef colorSpace	=
		CGColorSpaceCreateWithName(kCGColorSpaceGenericRGB);

	if (!colorSpace)
	{
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

#endif

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

#if	_INSANE_OPTIMIZATION_
//	setSize:
// ----------------------------------------------------------------------------

- (void)setSize: (NSSize)inSize
{
	[super setSize: inSize];

	CGFunctionCallbacks	cgCallback = {0 , &Evaluate, nil};

	// CGFunctionCreate() cannot fail. Nice.
	mGradientFunc	= CGFunctionCreate(
		&mData, 1, gInputRange, 4, gOutputRanges, &cgCallback);

	[self lockFocus];

	CGPoint	startPoint	= CGPointMake(0.0, inSize.height);
	CGPoint	endPoint	= CGPointMake(0.0, 0.0);

	CGContextRef	savedContext	=
		(CGContextRef)[[NSGraphicsContext currentContext] graphicsPort];

	CGContextSaveGState(savedContext);

	// CGColorSpaceCreateWithName() CAN fail.
	CGColorSpaceRef colorSpace	=
		CGColorSpaceCreateWithName(kCGColorSpaceGenericRGB);

	if (!colorSpace)
	{
		fprintf(stderr, "[GradientImage setSize:] "
			"unable to create CGColorSpace\n");
		return;
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
#endif

@end
