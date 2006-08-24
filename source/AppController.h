#import <Cocoa/Cocoa.h>
#import <Kernel/mach-o/loader.h>

#define kOutputTextTag		100
#define kOutputFileBaseTag	200
#define kOutputFileExtTag	201

// ============================================================================

@interface AppController : NSObject
{
// main window
	IBOutlet NSWindow*				mMainWindow;
	IBOutlet NSDrawer*				mProgDrawer;
	IBOutlet NSPopUpButton*			mArchPopup;
	IBOutlet NSButton*				mThinButton;
	IBOutlet NSTextField*			mOutputText;
	IBOutlet NSTextField*			mPathText;
	IBOutlet NSTextField*			mProgText;
	IBOutlet NSProgressIndicator*	mProgBar;
	IBOutlet NSButton*				mSaveButton;
	IBOutlet NSTextField*			mTypeText;
	IBOutlet struct CDropBox*		mDropBox;

// prefs window
	IBOutlet NSWindow*				mPrefsWindow;
	IBOutlet NSSegmentedControl*	mPrefsViewPicker;
	IBOutlet NSView*				mPrefsProcessView;
	IBOutlet NSView*				mPrefsOutputView;
	IBOutlet NSTextField*			mPrefsOutFileBaseText;
	IBOutlet NSTextField*			mPrefsOutFileExtText;

// about window
	IBOutlet NSPanel*				mAboutPanel;

// menus
	IBOutlet NSMenuItem*			mSaveMenuItem;

@private
	NSURL*				mOFile;
	char*				mRAMFile;
	cpu_type_t			mArchSelector;
	UInt32				mArchMagic;
	BOOL				mExeIsFat;
	BOOL				mFileIsValid;
	NSString*			mExeName;
	NSString*			mOutputFileLabel;
	NSString*			mOutputFileName;
	NSString*			mOutputFilePath;
	NSView**			mPrefsViews;
	UInt32				mPrefsCurrentViewIndex;
}

- (void)registerUserDefaults;

- (SInt32)checkOtool;

// main window
- (IBAction)showMainWindow: (id)sender;
- (IBAction)selectArch: (id)sender;
- (IBAction)openExe: (id)sender;
- (IBAction)syncOutputText: (id)sender;
- (IBAction)processFile: (id)sender;
- (IBAction)thinFile: (id)sender;
- (void)syncSaveButton;
- (void)syncDescriptionText;
- (void)newPackageFile: (NSURL*)inPackageFile;
- (void)newOFile: (NSURL*)inOFile
	   needsPath: (BOOL)inNeedsPath;

// other windows
- (IBAction)showPrefs: (id)sender;
- (IBAction)showAboutBox: (id)sender;
- (IBAction)switchPrefsViews: (id)sender;

// alerts
- (void)doOtoolAlertSheet;
- (void)doLipoAlertSheet;
- (void)doErrorAlertSheet;
- (void)doDrillErrorAlert: (NSString*)inExePath;

@end
