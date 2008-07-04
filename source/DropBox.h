/*
    DropBox.h

    A subclass of NSBox that implements drag n drop. Drag hiliting mimics
    NSTextField's focus border.

    This file is in the public domain.
*/

#import <Cocoa/Cocoa.h>

// Keep these <= 255 please.
#define kBorderWidth            6
#define kTexturedBorderWidth    7

#define kFillAlpha              0.06

// Alpha values for each one-pixel frame, from outer to inner. The
// outermost frame(s) overlay NSBox's border.
static const float  gAlphas[4][kBorderWidth]    =
    {{0.9, 0.7, 0.5, 0.3, 0.2, 0.0},    // NSNoBorder
     {0.4, 0.9, 0.6, 0.3, 0.2, 0.0},    // NSLineBorder
     {0.4, 0.4, 0.8, 0.6, 0.4, 0.2},    // NSBezelBorder
     {0.4, 0.4, 0.8, 0.6, 0.4, 0.2}};   // NSGrooveBorder

// Textured windows require a bit more.
static const float  gTexturedAlphas[4][kTexturedBorderWidth]    =
    {{1.0, 0.9, 0.8, 0.6, 0.4, 0.2, 0.0},   // NSNoBorder
     {0.4, 1.0, 0.8, 0.6, 0.4, 0.2, 0.0},   // NSLineBorder
     {0.4, 0.4, 1.0, 0.8, 0.6, 0.4, 0.2},   // NSBezelBorder
     {0.4, 0.4, 1.0, 0.8, 0.6, 0.4, 0.2}};  // NSGrooveBorder

// Leopard textured windows require a bit less.
static const float  gLeopardTexturedAlphas[4][kTexturedBorderWidth] =
   {{1.0, 0.8, 0.6, 0.4, 0.2, 0.0, 0.0},    // NSNoBorder
    {0.4, 0.8, 0.6, 0.4, 0.2, 0.0, 0.0},    // NSLineBorder
    {0.4, 0.4, 0.8, 0.6, 0.4, 0.2, 0.0},    // NSBezelBorder
    {0.4, 0.4, 0.8, 0.6, 0.4, 0.2, 0.0}};   // NSGrooveBorder

// ============================================================================

@interface DropBox : NSBox
{
    IBOutlet id iDelegate;

    BOOL        iShowHilite;
    BOOL        iFillRect;
}

- (void)setFillsRect: (BOOL)inFill;

@end

@interface NSObject(DropBoxDelegate)

- (NSDragOperation)dropBox: (DropBox*)inDropBox
              dragDidEnter: (id <NSDraggingInfo>)inItem;
- (void)dropBox: (DropBox*)inDropBox
    dragDidExit: (id <NSDraggingInfo>)inItem;
- (BOOL)dropBox: (DropBox*)inDropBox
 didReceiveItem: (id <NSDraggingInfo>)inItem;

@end