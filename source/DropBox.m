/*
	DropBox.m

	A subclass of NSBox that implements drag n drop. Drag hiliting mimics
	NSTextField's focus border.

	This file is in the public domain.
*/

#import "DropBox.h"

// ============================================================================

@implementation DropBox

//	awakeFromNib
// ----------------------------------------------------------------------------

- (void)awakeFromNib
{
	[self registerForDraggedTypes:
		[NSArray arrayWithObject: NSFilenamesPboardType]];
}

//	setFillsRect:
// ----------------------------------------------------------------------------
//	Call setFillsRect: YES to draw hilite the entire frame with kFillAlpha.

- (void)setFillsRect: (BOOL)inFill
{
	mFillRect	= inFill;
}

//	draggingEntered:
// ----------------------------------------------------------------------------

- (NSDragOperation)draggingEntered: (id<NSDraggingInfo>)sender
{
	NSDragOperation	dragOp	= NSDragOperationNone;

	if (delegate && [delegate respondsToSelector:
		@selector(dropBox:dragDidEnter:)])
		dragOp	= [delegate dropBox: self dragDidEnter: sender];

	if (dragOp == NSDragOperationNone)
		return dragOp;

	mShowHilite	= true;
	[self setNeedsDisplay: true];

	return dragOp;
}

//	draggingExited:
// ----------------------------------------------------------------------------

- (void)draggingExited: (id<NSDraggingInfo>)sender
{
	mShowHilite	= false;
	[self setNeedsDisplay: true];

	if (delegate && [delegate respondsToSelector:
		@selector(dropBox:dragDidExit:)])
		[delegate dropBox: self dragDidExit: sender];
}

//	performDragOperation:
// ----------------------------------------------------------------------------

- (BOOL)performDragOperation: (id<NSDraggingInfo>)sender
{
	mShowHilite	= false;
	[self setNeedsDisplay: true];

	if (!delegate)
		return false;

	if ([delegate respondsToSelector: @selector(dropBox:didReceiveItem:)])
		return [delegate dropBox: self didReceiveItem: sender];

	return false;
}

//	drawRect:
// ----------------------------------------------------------------------------

- (void)drawRect: (NSRect)rect
{
	[super drawRect: rect];

	if (!mShowHilite)
		return;

	NSBorderType	borderType	= [self borderType];

	if (borderType < 0 || borderType > 3)
	{
		fprintf(stderr, "DropBox: invalid NSBorderType: %d\n", borderType);
		return;
	}

	NSWindow*	window	= [self window];
	UInt8		borderWidth;
	BOOL		isTextured;

	if (window && ([window styleMask] & NSTexturedBackgroundWindowMask))
	{
		isTextured	= true;
		borderWidth	= kTexturedBorderWidth;
	}
	else
	{
		isTextured	= false;
		borderWidth	= kBorderWidth;
	}

	NSRect		innerRect	= rect;
	NSColor*	baseColor	= [NSColor keyboardFocusIndicatorColor];
	NSColor*	color;
	UInt8		i;

	for (i = 0; i < borderWidth; i++)
	{
		color	= [baseColor colorWithAlphaComponent: (isTextured) ?
			gTexturedAlphas[borderType][i] : gAlphas[borderType][i]];
		[color set];
		NSFrameRectWithWidthUsingOperation(
			innerRect, 1.0, NSCompositeSourceOver);
		innerRect	= NSInsetRect(innerRect, 1.0, 1.0);
	}

	if (mFillRect)
	{
		if (borderType == NSNoBorder || borderType == NSLineBorder)
			innerRect	= NSInsetRect(innerRect, -1.0, -1.0);

		color	= [baseColor colorWithAlphaComponent: kFillAlpha];
		[color set];
		NSRectFillUsingOperation(innerRect, NSCompositeSourceOver);
	}
}

@end
