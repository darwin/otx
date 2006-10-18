/*
	CDropBox.h
*/

#import "AppController.h"

#define kBorderWidth	3.0

@interface CDropBox : NSBox
{
	IBOutlet struct AppController*	mController;

	BOOL	mDragHilite;
}

@end
