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

//	draggingEntered:
// ----------------------------------------------------------------------------

- (NSDragOperation)draggingEntered: (id<NSDraggingInfo>)sender
{
	NSDragOperation	dragOp	= NSDragOperationNone;

	if (delegate)
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

	if (delegate)
		return [delegate dropBox: self dragDidExit: sender];
}

//	performDragOperation:
// ----------------------------------------------------------------------------

- (BOOL)performDragOperation: (id<NSDraggingInfo>)sender
{
	mShowHilite	= false;
	[self setNeedsDisplay: true];

	if (delegate)
		return [delegate dropBox: self didReceiveItem: sender];
	else
		return false;
}

//	drawRect:
// ----------------------------------------------------------------------------

- (void)drawRect: (NSRect)rect
{
	[super drawRect: rect];

	if (mShowHilite)
	{
		NSRect			innerRect	= rect;
		NSColor*		baseColor	= [NSColor keyboardFocusIndicatorColor];
		NSColor*		color;
		UInt8			i;
		NSBorderType	borderType	= [self borderType];

		if (borderType < 0 || borderType > 3)
		{
			fprintf(stderr, "invalid NSBorderType: %d\n", borderType);
			return;
		}

		for (i = 0; i < kBorderWidth; i++)
		{
			color	= [baseColor colorWithAlphaComponent:
				gAlphas[borderType][i]];
			[color set];
			NSFrameRectWithWidthUsingOperation(
				innerRect, 1.0, NSCompositeSourceOver);
			innerRect	= NSInsetRect(innerRect, 1.0, 1.0);
		}
	}
}

@end
