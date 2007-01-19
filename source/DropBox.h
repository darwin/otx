/*
	DropBox.h

	A subclass of NSBox that implements drag n drop. Drag hiliting mimics
	NSTextField's focus border.

	This file is in the public domain.
*/

#define	kBorderWidth	6

// Alpha values for each one-pixel frame, from outer to inner. The
// outermost frame(s) overlay NSBox's border.
static const float	gAlphas[4][kBorderWidth]	=
	{{1.0, 0.8, 0.6, 0.4, 0.2, 0.0},	// NSNoBorder
	 {0.5, 0.8, 0.6, 0.4, 0.2, 0.0},	// NSLineBorder
	 {0.5, 0.5, 0.8, 0.6, 0.4, 0.2},	// NSBezelBorder
	 {0.5, 0.5, 0.8, 0.6, 0.4, 0.2}};	// NSGrooveBorder

// ============================================================================

@interface DropBox : NSBox
{
    IBOutlet id		delegate;

	BOOL			mShowHilite;
}

@end

@interface NSObject(DropBoxDelegate)

- (NSDragOperation)dropBox: (DropBox*)inDropBox
			  dragDidEnter: (id <NSDraggingInfo>)inItem;
- (void)dropBox: (DropBox*)inDropBox
	dragDidExit: (id <NSDraggingInfo>)inItem;
- (BOOL)dropBox: (DropBox*)inDropBox
 didReceiveItem: (id <NSDraggingInfo>)inItem;

@end