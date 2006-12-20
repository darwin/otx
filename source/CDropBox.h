/*
	CDropBox.h

	A subclass of NSBox that implements drag n drop. Drag hiliting mimics
	NSTextField's focus border.

	This file is in the public domain.
*/

#import "AppController.h"

#define	kBorderWidth	5

// ============================================================================

@interface CDropBox : NSBox
{
	IBOutlet struct AppController*	mController;

	BOOL	mDragHilite;
	float	mAlphas[kBorderWidth];
}

@end
