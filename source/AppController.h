/*
	AppController.h

	This file is in the public domain.
*/

#import "DropBox.h"
#import "GradientImage.h"
#import "ProgressReporter.h"

#define kOutputTextTag		100
#define kOutputFileBaseTag	200
#define kOutputFileExtTag	201

#define	kPrefsAnimationTime	0.15
#define	kMainAnimationTime	0.15

#define kPolishedLightRed	0.800
#define kPolishedLightGreen	0.800
#define kPolishedLightBlue	0.810
#define kPolishedDarkRed	0.670
#define kPolishedDarkGreen	0.670
#define kPolishedDarkBlue	0.680

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
#define NSXViewAnimationPerformInNewThreadKey				\
	@"NSXViewAnimationPerformInNewThreadKey"				// NSNumber*(BOOL)

#define NSXViewAnimationOpenFileWithAppAtEndEffect			(1 << 5)
#define NSXViewAnimationFilePathKey							\
	@"NSXViewAnimationFilePathKey"							// NSString*
#define NSXViewAnimationAppNameKey							\
	@"NSXViewAnimationAppNameKey"							// NSString*

// ============================================================================

@interface AppController : NSObject<ProgressReporter>
{
// main window
	IBOutlet NSWindow*				mMainWindow;
	IBOutlet NSPopUpButton*			mArchPopup;
	IBOutlet NSButton*				mThinButton;
	IBOutlet NSButton*				mVerifyButton;
	IBOutlet NSTextField*			mOutputText;
	IBOutlet NSTextField*			mOutputLabelText;
	IBOutlet NSTextField*			mPathText;
	IBOutlet NSTextField*			mPathLabelText;
	IBOutlet NSTextField*			mProgText;
	IBOutlet NSTextField*			mTypeText;
	IBOutlet NSTextField*			mTypeLabelText;
	IBOutlet NSProgressIndicator*	mProgBar;
	IBOutlet NSButton*				mSaveButton;
	IBOutlet DropBox*				mDropBox;
	IBOutlet NSView*				mMainView;
	IBOutlet NSView*				mProgView;

// prefs window
	IBOutlet NSWindow*				mPrefsWindow;
	IBOutlet NSSegmentedControl*	mPrefsViewPicker;
	IBOutlet NSView*				mPrefsGeneralView;
	IBOutlet NSView*				mPrefsOutputView;

@private
	NSURL*						mOFile;
	char*						mRAMFile;
	cpu_type_t					mArchSelector;
	UInt32						mArchMagic;
	BOOL						mFileIsValid;
	BOOL						mIgnoreArch;
	BOOL						mExeIsFat;
	BOOL						mProcessing;
	NSString*					mExeName;
	NSString*					mOutputFileLabel;
	NSString*					mOutputFileName;
	NSString*					mOutputFilePath;
	NSView**					mPrefsViews;
	UInt32						mPrefsCurrentViewIndex;
	host_basic_info_data_t		mHostInfo;
	NSColor*					mPolishedLightColor;
	NSColor*					mPolishedDarkColor;
	NSShadow*					mTextShadow;
}

- (SInt32)checkOtool;

// main window
- (void)setupMainWindow;
- (IBAction)showMainWindow: (id)sender;
- (void)drawMainWindowBackground;
- (void)applyShadowToText: (NSTextField*)inText;
- (IBAction)selectArch: (id)sender;
- (IBAction)openExe: (id)sender;
- (IBAction)syncOutputText: (id)sender;
- (IBAction)processFile: (id)sender;
- (void)continueProcessingFile;
- (void)adjustInterfaceForMultiThread;
- (void)adjustInterfaceForSingleThread;
- (void)processingThreadDidFinish: (BOOL)successfully;
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
- (void)hideProgView: (BOOL)inAnimate
			openFile: (BOOL)inOpenFile;

// prefs window
- (IBAction)showPrefs: (id)sender;
- (IBAction)switchPrefsViews: (id)sender;

// alerts
- (void)doOtoolAlert;
- (void)doLipoAlert;
- (void)doErrorAlert;

@end
