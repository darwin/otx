/*
	CDropBox.m

	A subclass of NSBox that implements drag n drop. Drag hiliting mimics
	NSTextField's focus border.

	This file is in the public domain.
*/

#import "CDropBox.h"

// ============================================================================

@implementation CDropBox

//	awakeFromNib
// ----------------------------------------------------------------------------

- (void)awakeFromNib
{
	[self registerForDraggedTypes:
		[NSArray arrayWithObject: NSFilenamesPboardType]];

	// Alpha values for each one-pixel frame, from outer to inner. The
	// outermost frame overlays NSBox's standard border.
	mAlphas[0]	= 0.5;
	mAlphas[1]	= 0.8;
	mAlphas[2]	= 0.6;
	mAlphas[3]	= 0.4;
	mAlphas[4]	= 0.2;
}

//	draggingEntered:
// ----------------------------------------------------------------------------

- (NSDragOperation)draggingEntered: (id <NSDraggingInfo>)sender
{
	NSPasteboard*	thePasteBoard	= [sender draggingPasteboard];

	// bail if not a file.
	if (![[thePasteBoard types] containsObject: NSFilenamesPboardType])
		return NSDragOperationNone;

	NSArray*	theFiles	= [thePasteBoard
		propertyListForType: NSFilenamesPboardType];

	// bail if not a single file.
	if ([theFiles count] != 1)
		return NSDragOperationNone;

	NSDragOperation	theSourceDragMask	= [sender draggingSourceOperationMask];

	// bail if modifier keys pressed.
	if (!(theSourceDragMask & NSDragOperationLink))
		return NSDragOperationNone;

	mDragHilite	= true;
	[self setNeedsDisplay: true];
	return NSDragOperationLink;
}

//	draggingExited:
// ----------------------------------------------------------------------------

- (void)draggingExited: (id <NSDraggingInfo>)sender
{
	mDragHilite	= false;
	[self setNeedsDisplay: true];
}

//	performDragOperation:
// ----------------------------------------------------------------------------

- (BOOL)performDragOperation: (id <NSDraggingInfo>)sender
{
	NSURL*	theURL	= [NSURL URLFromPasteboard: [sender draggingPasteboard]];

	if ([[NSWorkspace sharedWorkspace] isFilePackageAtPath: [theURL path]])
		[mController newPackageFile: theURL];
	else
		[mController newOFile: theURL needsPath: true];

	mDragHilite	= false;
	[self setNeedsDisplay: true];
	return true;
}

//	drawRect:
// ----------------------------------------------------------------------------

- (void)drawRect: (NSRect)rect
{
	[super drawRect: rect];

//	if (mDragHilite)
//	{
		NSRect		innerRect	= rect;
		NSColor*	baseColor	= [NSColor keyboardFocusIndicatorColor];
		NSColor*	color;
		UInt8		i;

		for (i = 0; i < kBorderWidth; i++)
		{
			color	= [baseColor colorWithAlphaComponent: mAlphas[i]];
			[color set];
			NSFrameRectWithWidthUsingOperation(
				innerRect, 1.0, NSCompositeSourceOver);
			innerRect	= NSInsetRect(innerRect, 1.0, 1.0);
		}
//	}
}

@end
