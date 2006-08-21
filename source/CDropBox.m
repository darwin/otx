#import "CDropBox.h"

@implementation CDropBox

//	awakeFromNib
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)awakeFromNib
{
	[self registerForDraggedTypes:
		[NSArray arrayWithObject: NSFilenamesPboardType]];
}

//	draggingEntered:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (NSDragOperation)draggingEntered: (id <NSDraggingInfo>)sender
{
	NSPasteboard*	thePasteBoard	= [sender draggingPasteboard];

	// bail if not a file.
	if (![[thePasteBoard types] containsObject: NSFilenamesPboardType])
		return NSDragOperationNone;

	NSArray*	theFiles	= [thePasteBoard
		propertyListForType: NSFilenamesPboardType];

	// bail if more than one file.
	if ([theFiles count] != 1)
		return NSDragOperationNone;

    NSDragOperation	theSourceDragMask	=
		[sender draggingSourceOperationMask];

	// bail if modifier keys pressed.
	if (!(theSourceDragMask & NSDragOperationLink))
		return NSDragOperationNone;

	mDragHilite	= true;
	[self setNeedsDisplay: true];
	return NSDragOperationLink;
}

//	draggingExited:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)draggingExited: (id <NSDraggingInfo>)sender
{
	mDragHilite	= false;
	[self setNeedsDisplay: true];
}

//	performDragOperation:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (BOOL)performDragOperation: (id <NSDraggingInfo>)sender
{
	NSURL*		theURL		= [NSURL URLFromPasteboard:
		[sender draggingPasteboard]];

	if ([[NSWorkspace sharedWorkspace] isFilePackageAtPath: [theURL path]])
		[mController newPackageFile: theURL];
	else
		[mController newOFile: theURL needsPath: true];

	mDragHilite	= false;
	[self setNeedsDisplay: true];
	return true;
}

//	drawRect:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

-(void)drawRect: (NSRect)rect
{
	[super drawRect: rect];

	if (mDragHilite)
	{
		[[NSColor keyboardFocusIndicatorColor] set];
		[NSBezierPath setDefaultLineWidth: kBorderWidth];
		[NSBezierPath strokeRect: rect];
	}
}

@end
