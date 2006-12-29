/*
	SmoothViewAnimation.m

	Adapted from the smooth animation example in
	http://developer.apple.com/documentation/Cocoa/Conceptual/AnimationGuide/AnimationGuide.pdf
	This version caches the window in the new init method, and asks the window
	for it's screen, rather than using the main screen. It also no longer
	tweaks the window's origin. Used only in otx Preferences window, it has
	not been tested with horizontal resizement.

	This file is in the public domain.
*/

#import "SmoothViewAnimation.h"

// ============================================================================

@implementation SmoothViewAnimation

//	initWithViewAnimations:andWindow:
// ----------------------------------------------------------------------------

- (id)initWithViewAnimations: (NSArray*)viewAnimations
				   andWindow: (NSWindow*)inWindow
{
	self = [super initWithViewAnimations: viewAnimations];

	if (self)
		mWindow	= inWindow;

	return self;
}

//	setCurrentProgress:
// ----------------------------------------------------------------------------

- (void)setCurrentProgress: (NSAnimationProgress)progress
{
	// Call super to update the progress value.
	[super setCurrentProgress: progress];

	if (!mWindow)	// can't do much without a window
		return;

	// Update the window position. As stupid as this looks, [mWindow display]
	// just doesn't cut it.
	[mWindow setFrame: [mWindow frame] display: true animate: true];
}

@end
