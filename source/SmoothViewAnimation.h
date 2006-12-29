/*
	SmoothViewAnimation.h

	This file is in the public domain.
*/

#import <Cocoa/Cocoa.h>

// ============================================================================

@interface SmoothViewAnimation : NSViewAnimation
{
	NSWindow*	mWindow;
}

- (id)initWithViewAnimations: (NSArray*)viewAnimations
				   andWindow: (NSWindow*)inWindow;

@end
