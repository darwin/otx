/*
	AppController.h

	This file is in the public domain.
*/

#import "DropBox.h"
#import "ProgressReporter.h"

#define kOutputTextTag		100
#define kOutputFileBaseTag	200
#define kOutputFileExtTag	201

#define	kPrefsAnimationTime	.15
#define	kMainAnimationTime	.15

#define NSXViewAnimationCustomEffectsKey	@"NSXViewAnimationCustomEffectsKey"

#define NSXViewAnimationSwapAtBeginningEffect				(1 << 0)
#define NSXViewAnimationSwapAtEndEffect						(1 << 1)
#define NSXViewAnimationSwapOldKey							\
	@"NSXViewAnimationSwapOldKey"							// NSView*
#define NSXViewAnimationSwapNewKey							\
	@"NSXViewAnimationSwapNewKey"							// NSView*

#define NSXViewAnimationUpdateResizeMasksAtEndEffect		(1 << 2)
#define NSXViewAnimationResizeMasksArrayKey					\
	@"NSXViewAnimationResizeMasksArrayKey"					// NSArray*(UInt32)
#define NSXViewAnimationResizeViewsArrayKey					\
	@"NSXViewAnimationResizeViewsArrayKey"					// NSArray*(UInt32)

#define NSXViewAnimationUpdateWindowMinMaxSizesAtEndEffect	(1 << 3)
#define NSXViewAnimationWindowMinSizeKey					\
	@"NSXViewAnimationWindowMinSizeKey"						// NSValue*(NSSize*)
#define NSXViewAnimationWindowMaxSizeKey					\
	@"NSXViewAnimationWindowMaxSizeKey"						// NSValue*(NSSize*)

#define NSXViewAnimationPerformSelectorAtEndEffect			(1 << 4)
#define NSXViewAnimationSelectorKey							\
	@"NSXViewAnimationSelectorKey"							// NSValue*(SEL)

// ============================================================================

@interface AppController : NSObject <ProgressReporter>
{
// main window
	IBOutlet NSWindow*				mMainWindow;
	IBOutlet NSDrawer*				mProgDrawer;
	IBOutlet NSPopUpButton*			mArchPopup;
	IBOutlet NSButton*				mThinButton;
	IBOutlet NSButton*				mVerifyButton;
	IBOutlet NSTextField*			mOutputText;
	IBOutlet NSTextField*			mPathText;
	IBOutlet NSTextField*			mProgText;
	IBOutlet NSProgressIndicator*	mProgBar;
	IBOutlet NSButton*				mSaveButton;
	IBOutlet NSTextField*			mTypeText;
	IBOutlet DropBox*				mDropBox;
	IBOutlet NSView*				mProgView;
	IBOutlet NSView*				mMainView;

// prefs window
	IBOutlet NSWindow*				mPrefsWindow;
	IBOutlet NSSegmentedControl*	mPrefsViewPicker;
	IBOutlet NSView*				mPrefsGeneralView;
	IBOutlet NSView*				mPrefsOutputView;

@private
	NSURL*					mOFile;
	char*					mRAMFile;
	cpu_type_t				mArchSelector;
	UInt32					mArchMagic;
	BOOL					mFileIsValid;
	BOOL					mIgnoreArch;
	NSString*				mExeName;
	NSString*				mOutputFileLabel;
	NSString*				mOutputFileName;
	NSString*				mOutputFilePath;
	NSView**				mPrefsViews;
	UInt32					mPrefsCurrentViewIndex;
	host_basic_info_data_t	mHostInfo;

	UInt32					mOrigMainViewMask;	// lose
	UInt32					mOrigProgViewMask;	// lose
}

- (SInt32)checkOtool;

// main window
- (IBAction)showMainWindow: (id)sender;
- (IBAction)selectArch: (id)sender;
- (IBAction)openExe: (id)sender;
- (IBAction)syncOutputText: (id)sender;
- (IBAction)processFile: (id)sender;
- (void)continueProcessingFile;
- (IBAction)thinFile: (id)sender;
- (IBAction)verifyNops: (id)sender;
- (void)syncSaveButton;
- (void)syncDescriptionText;
- (void)newPackageFile: (NSURL*)inPackageFile;
- (void)newOFile: (NSURL*)inOFile
	   needsPath: (BOOL)inNeedsPath;
- (void)nopAlertDidEnd: (NSAlert*)alert
			returnCode: (int)returnCode
		   contextInfo: (void*)contextInfo;
- (void)showProgView;
- (void)hideProgView: (BOOL)inAnimate;

// prefs window
- (IBAction)showPrefs: (id)sender;
- (IBAction)switchPrefsViews: (id)sender;

// alerts
- (void)doOtoolAlert;
- (void)doLipoAlert;
- (void)doErrorAlert;
- (void)doDrillErrorAlert: (NSString*)inExePath;

@end
