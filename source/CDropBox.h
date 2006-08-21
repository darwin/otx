#import "AppController.h"

#define kBorderWidth	6

@interface CDropBox : NSBox
{
	IBOutlet struct AppController*	mController;

	BOOL	mDragHilite;
}

@end
