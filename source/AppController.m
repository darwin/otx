#import <mach-o/fat.h>
#import <sys/types.h>
#import <sys/ptrace.h>
#import <sys/syscall.h>

#import "AppController.h"
#import "ExeProcessor.h"
#import "PPCProcessor.h"
#import "X86Processor.h"
#import "UserDefaultKeys.h"

@implementation AppController

//	init
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (id)init
{
	self = [super init];	// with apologies to Wil Shipley
	return self;
}

//	initialize
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

+ (void)initialize
{
	NSUserDefaultsController*	theController	=
		[NSUserDefaultsController sharedUserDefaultsController];
	NSDictionary*				theValues		=
		[NSDictionary dictionaryWithObjectsAndKeys:
		@"1",		AskOutputDirKey,
		@"YES",		DemangleCppNamesKey,
		@"YES",		EntabOutputKey,
		@"YES",		OpenOutputFileKey,
		@"BBEdit",	OutputAppKey,
		@"txt",		OutputFileExtensionKey,
		@"output",	OutputFileNameKey,
		@"YES",		ShowDataSectionKey,
		@"YES",		ShowIvarTypesKey,
		@"YES",		ShowLocalOffsetsKey,
		@"YES",		ShowMD5Key,
		@"YES",		ShowMethodReturnTypesKey,
		@"0",		UseCustomNameKey,
		nil];

	[theController setInitialValues: theValues];
	[[theController defaults] registerDefaults: theValues];
}

//	dealloc
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)dealloc
{
	if (mOFile)
		[mOFile release];

	if (mExeName)
		[mExeName release];

	if (mOutputFileLabel)
		[mOutputFileLabel release];

	if (mOutputFileName)
		[mOutputFileName release];

	if (mOutputFilePath)
		[mOutputFilePath release];

	if (mPrefsViews)
		free(mPrefsViews);

	[super dealloc];
}

//	applicationDidFinishLaunching:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)applicationDidFinishLaunching: (NSNotification*)inNotification
{
	// Setup prefs window
	UInt32	numViews	= [mPrefsViewPicker segmentCount];
	UInt32	i;

	mPrefsCurrentViewIndex	= 0;
	mPrefsViews				= calloc(numViews, sizeof(NSView*));
	mPrefsViews[0]			= mPrefsProcessView;
	mPrefsViews[1]			= mPrefsOutputView;

	[mPrefsWindow setFrame: [mPrefsWindow frameRectForContentRect:
		[mPrefsViews[0] frame]] display: false];

	for (i = 0; i < numViews; i++)
	{
		[[mPrefsWindow contentView] addSubview: mPrefsViews[i]
			positioned: NSWindowBelow relativeTo: mPrefsViewPicker];
	}

	// Show main window
	[mMainWindow setFrameAutosaveName: [mMainWindow title]];
	[mMainWindow center];
	[mMainWindow makeKeyAndOrderFront: nil];
}

//	windowDidResize:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)windowDidResize: (NSNotification*)inNotification
{
	if ([inNotification object] == mMainWindow)
		[mMainWindow display];
}

//	openExe:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ
//	Open from File menu. Packages are treated as directories, so we can get
//	at frameworks, bundles etc.

- (IBAction)openExe: (id)sender
{
	NSOpenPanel*	thePanel	= [NSOpenPanel openPanel];

	[thePanel setTreatsFilePackagesAsDirectories: true];

	if ([thePanel runModalForTypes: nil] != NSFileHandlingPanelOKButton)
		return;

	NSString*	theName	= [[thePanel filenames] objectAtIndex: 0];

	[self newOFile: [NSURL fileURLWithPath: theName] needsPath: true];
}

//	application:openFile:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ
//	Open by drag n drop from Finder.

- (BOOL)application: (NSApplication*)sender
		   openFile: (NSString*)filename
{
	if ([[NSWorkspace sharedWorkspace] isFilePackageAtPath: filename])
		[self newPackageFile: [NSURL fileURLWithPath: filename]];
	else
		[self newOFile: [NSURL fileURLWithPath: filename] needsPath: true];

	return true;
}

#pragma mark -
//	controlTextDidChange:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)controlTextDidChange: (NSNotification*)inNotification
{
	switch ([[inNotification object] tag])
	{
		case kOutputTextTag:
			[self syncSaveButton];
			break;

		case kOutputFileBaseTag:
		case kOutputFileExtTag:
			[self syncOutputText: nil];
			break;

		default:
			break;
	}
}

//	newPackageFile:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ
//	Attempt to drill into the package to the executable. Fails when exe name
//	is different from app name, and when the exe is unreadable.

- (void)newPackageFile: (NSURL*)inPackageFile
{
	if (mOutputFilePath)
		[mOutputFilePath release];

	mOutputFilePath	= [inPackageFile path];
	[mOutputFilePath retain];

	NSString*		theExeName	=
		[[mOutputFilePath stringByDeletingPathExtension] lastPathComponent];
	NSString*		theExePath	=
	[[[mOutputFilePath stringByAppendingPathComponent: @"Contents"]
		stringByAppendingPathComponent: @"MacOS"]
		stringByAppendingPathComponent: theExeName];
	NSFileManager*	theFileMan	= [NSFileManager defaultManager];

	if ([theFileMan isExecutableFileAtPath: theExePath])
		[self newOFile: [NSURL fileURLWithPath: theExePath] needsPath: false];
	else
		[self doDrillErrorAlert: theExePath];
}

//	newOFile:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)newOFile: (NSURL*)inOFile
	   needsPath: (BOOL)inNeedsPath
{
	if (mOFile)
		[mOFile release];

	if (mExeName)
		[mExeName release];

	mOFile	= inOFile;
	[mOFile retain];

	if (inNeedsPath)
	{
		if (mOutputFilePath)
			[mOutputFilePath release];

		mOutputFilePath	= [mOFile path];
		[mOutputFilePath retain];
	}

	mExeName	= [[mOutputFilePath
		stringByDeletingPathExtension] lastPathComponent];
	[mExeName retain];

	[self syncDescriptionText];
	[self syncOutputText: nil];
	[self syncSaveButton];
}

#pragma mark -
//	showMainWindow
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (IBAction)showMainWindow: (id)sender
{
	if (!mMainWindow)
	{
		printf("otx: failed to load MainMenu.nib\n");
		return;
	}

	[mMainWindow makeKeyAndOrderFront: nil];
}

//	selectArch:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (IBAction)selectArch: (id)sender
{
	mArchSelector	= [[mArchPopup selectedItem] tag];

	if (mOutputFileLabel)
	{
		[mOutputFileLabel release];
		mOutputFileLabel	= nil;
	}

	switch (mArchSelector)
	{
		case CPU_TYPE_POWERPC:
			mOutputFileLabel	= @"_PPC";
			break;
		case CPU_TYPE_I386:
			mOutputFileLabel	= @"_x86";
			break;

		default:
			break;
	}

	if (mOutputFileLabel)
		[mOutputFileLabel retain];

	[self syncOutputText: nil];
	[self syncSaveButton];
}

//	processFile:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (IBAction)processFile: (id)sender
{
	if (mOutputFileName)
		[mOutputFileName release];

	mOutputFileName	= [mOutputText stringValue];
	[mOutputFileName retain];

	NSString*	theTempOutputFilePath	= mOutputFilePath;

	[theTempOutputFilePath retain];

	if ([[NSUserDefaults standardUserDefaults] boolForKey: AskOutputDirKey])
	{
		NSSavePanel*	thePanel	= [NSSavePanel savePanel];

		[thePanel setTreatsFilePackagesAsDirectories: true];

		if ([thePanel runModalForDirectory: nil
			file: mOutputFileName]	!= NSFileHandlingPanelOKButton)
			return;

		if (mOutputFilePath)
			[mOutputFilePath release];

		mOutputFilePath	= [thePanel filename];
	}
	else
	{
		mOutputFilePath	=
			[[theTempOutputFilePath stringByDeletingLastPathComponent]
			stringByAppendingPathComponent: [mOutputText stringValue]];
	}

	[mOutputFilePath retain];
	[theTempOutputFilePath release];

	[mProgText setStringValue: @"Loading executable"];
	[mProgDrawer setContentSize: [mProgDrawer maxContentSize]];
	[mProgDrawer openOnEdge: NSMinYEdge];	// Min Y = 'bottom'
}

//	thinFile:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ
//	Use lipo to separate out the currently selected arch from a unibin.

- (IBAction)thinFile: (id)sender
{
	NSString*	theThinOutputPath		= nil;

	if ([[NSUserDefaults standardUserDefaults] boolForKey: AskOutputDirKey])
	{
		NSSavePanel*	thePanel	= [NSSavePanel savePanel];
		NSString*		theFileName	= [mExeName stringByAppendingString:
			(mArchSelector == CPU_TYPE_POWERPC) ? @"_PPC" : @"_x86"];

		[thePanel setTreatsFilePackagesAsDirectories: true];

		if ([thePanel runModalForDirectory: nil
			file: theFileName]	!= NSFileHandlingPanelOKButton)
			return;

		theThinOutputPath	= [thePanel filename];
	}
	else
	{
		theThinOutputPath	=
			[[mOutputFilePath stringByDeletingPathExtension]
				stringByAppendingString:
				(mArchSelector == CPU_TYPE_POWERPC) ? @"_PPC" : @"_x86"];
	}

	NSString*	lipoString	= [NSString stringWithFormat:
		@"lipo '%@' -output '%@' -thin %s", [mOFile path], theThinOutputPath,
		(mArchSelector == CPU_TYPE_POWERPC) ? "ppc" : "i386"];

	if (system([lipoString
		cStringUsingEncoding: NSMacOSRomanStringEncoding]) != 0)
		[self doLipoAlertSheet];
}

//	validateMenuItem
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (BOOL)validateMenuItem: (id<NSMenuItem>)menuItem
{
	if ([menuItem action] == @selector(processFile:))
	{
		NSUserDefaults*	theDefaults	= [NSUserDefaults standardUserDefaults];

		if ([theDefaults boolForKey: AskOutputDirKey])
			[menuItem setTitle: [NSString stringWithCString: "SaveÉ"
				encoding: NSMacOSRomanStringEncoding]];
		else
			[menuItem setTitle: @"Save"];

		return mFileIsValid;
	}

	return true;
}

#pragma mark -
//	syncSaveButton
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)syncSaveButton
{
	[mSaveButton setEnabled:
		(mFileIsValid && [[mOutputText stringValue] length] > 0)];
}

//	syncDescriptionText
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)syncDescriptionText
{
	BOOL			shouldEnableArch	= false;
	NSFileHandle*	theFileH			=
		[NSFileHandle fileHandleForReadingAtPath: [mOFile path]];

	if (!theFileH)
	{
		printf("otx: -[AppController syncDescriptionText] "
			"couldn't open executable file. returning.\n");
		return;
	}

	NSData*	theData	= [theFileH readDataOfLength: sizeof(mArchMagic)];

	mArchMagic		= *(UInt32*)[theData bytes];
	mFileIsValid	= true;

	[mPathText setStringValue: [mOFile path]];

	if (mOutputFileLabel)
	{
		[mOutputFileLabel release];
		mOutputFileLabel	= nil;
	}

	switch (mArchMagic)
	{
		case MH_MAGIC:
			if (OSHostByteOrder() == OSBigEndian)
			{
				mArchSelector	= CPU_TYPE_POWERPC;
				[mTypeText setStringValue: @"PPC"];
			}
			else
			{
				mArchSelector	= CPU_TYPE_I386;
				[mTypeText setStringValue: @"x86"];
			}

			break;

		case MH_CIGAM:
			if (OSHostByteOrder() == OSBigEndian)
			{
				mArchSelector	= CPU_TYPE_I386;
				[mTypeText setStringValue: @"x86"];
			}
			else
			{
				mArchSelector	= CPU_TYPE_POWERPC;
				[mTypeText setStringValue: @"PPC"];
			}

			break;

		case FAT_MAGIC:
		case FAT_CIGAM:
			if (OSHostByteOrder() == OSBigEndian)
			{
				mArchSelector		= CPU_TYPE_POWERPC;
				mOutputFileLabel	= @"_PPC";
			}
			else
			{
				mArchSelector		= CPU_TYPE_I386;
				mOutputFileLabel	= @"_x86";
			}

			shouldEnableArch	= true;
			[mTypeText setStringValue: @"Fat"];
			break;

		default:
			mFileIsValid	= false;
			mArchSelector	= 0;
			[mTypeText setStringValue: @"Not a Mach-O file"];
			break;
	}

	if (mOutputFileLabel)
		[mOutputFileLabel retain];

	if (mArchSelector)
		[mArchPopup selectItemWithTag: mArchSelector];

	[mThinButton setEnabled: shouldEnableArch];
	[mArchPopup setEnabled: shouldEnableArch];
	[mArchPopup synchronizeTitleAndSelectedItem];
}

//	syncOutputText:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (IBAction)syncOutputText: (id)sender
{
	if (!mFileIsValid)
		return;

	NSUserDefaults*	theDefaults	= [NSUserDefaults standardUserDefaults];
	NSString*		theString	= nil;

	if ([theDefaults boolForKey: UseCustomNameKey])
		theString	= [theDefaults objectForKey: OutputFileNameKey];
	else
		theString	= mExeName;

	if (!theString)
		theString	= @"error";

	NSString*	theExt	= [theDefaults objectForKey: OutputFileExtensionKey];

	if (!theExt)
		theExt	= @"error";

	if (mOutputFileLabel)
		theString	= [theString stringByAppendingString: mOutputFileLabel];

	theString	= [theString stringByAppendingPathExtension: theExt];

	if (theString)
		[mOutputText setStringValue: theString];
	else
		[mOutputText setStringValue: @"ERROR.FUKT"];
}

#pragma mark -
//	drawerDidOpen:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)drawerDidOpen: (NSNotification*)notification
{
	if ([notification object] != mProgDrawer || !mOFile)
		return;

	mExeIsFat	= mArchMagic == FAT_MAGIC || mArchMagic == FAT_CIGAM;

	if ([self checkOtool] != noErr)
	{
		printf("otx: otool not found\n");
		[self doOtoolAlertSheet];
		[mProgDrawer close];
		return;
	}

	switch (mArchSelector)
	{
		case CPU_TYPE_POWERPC:
		{
			PPCProcessor*	theProcessor	=
				[[PPCProcessor alloc] initWithURL: mOFile
				progText: mProgText progBar: mProgBar];

			if (!theProcessor)
			{
				printf("otx: couldn't create processor\n");
				return;
			}

			if (![theProcessor processExe: mOutputFilePath arch: mArchSelector])
			{
				printf("otx: possible permission error\n");
				[self doErrorAlertSheet];
				[theProcessor release];
				[mProgDrawer close];
				return;
			}

			[theProcessor release];

			break;
		}

		case CPU_TYPE_I386:
		{
			X86Processor*	theProcessor	=
				[[X86Processor alloc] initWithURL: mOFile
				progText: mProgText progBar: mProgBar];

			if (!theProcessor)
			{
				printf("otx: couldn't create processor\n");
				return;
			}

			if (![theProcessor processExe: mOutputFilePath arch: mArchSelector])
			{
				printf("otx: possible permission error\n");
				[self doErrorAlertSheet];
				[theProcessor release];
				[mProgDrawer close];
				return;
			}

			[theProcessor release];

			break;
		}

		default:
			break;
	}

	[mProgDrawer close];

	NSUserDefaults*	theDefaults	= [NSUserDefaults standardUserDefaults];

	if ([theDefaults boolForKey: OpenOutputFileKey])
		[[NSWorkspace sharedWorkspace] openFile: mOutputFilePath
			withApplication: [theDefaults objectForKey: OutputAppKey]];
}

//	drawerDidClose:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)drawerDidClose: (NSNotification*)notification
{
	if ([notification object] != mProgDrawer)
		return;

	[mProgBar setIndeterminate: true];
	[mProgBar setDoubleValue: 0];
}

#pragma mark -
//	checkOtool
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (SInt32)checkOtool
{
	char*		cmdString	= mExeIsFat ? "otool -f" : "otool -h";
	NSString*	otoolString	= [NSString stringWithFormat:
		@"%s '%@' > /dev/null", cmdString, [mOFile path]];

	return system(
		[otoolString cStringUsingEncoding: NSMacOSRomanStringEncoding]);
}

//	doOtoolAlertSheet
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)doOtoolAlertSheet
{
	NSAlert*	theAlert	= [[NSAlert alloc] init];

	[theAlert addButtonWithTitle: @"OK"];
	[theAlert setMessageText: @"otool was not found."];
	[theAlert setInformativeText: @"Please install otool and try again."];
	[theAlert beginSheetModalForWindow: mMainWindow
		modalDelegate: nil didEndSelector: nil contextInfo: nil];
	[theAlert release];
}

//	doLipoAlertSheet
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)doLipoAlertSheet
{
	NSAlert*	theAlert	= [[NSAlert alloc] init];

	[theAlert addButtonWithTitle: @"OK"];
	[theAlert setMessageText: @"lipo was not found."];
	[theAlert setInformativeText: @"Please install lipo and try again."];
	[theAlert beginSheetModalForWindow: mMainWindow
		modalDelegate: nil didEndSelector: nil contextInfo: nil];
	[theAlert release];
}

//	doErrorAlertSheet
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)doErrorAlertSheet
{
	NSAlert*	theAlert	= [[NSAlert alloc] init];

	[theAlert addButtonWithTitle: @"OK"];
	[theAlert setMessageText: @"Could not create file."];
	[theAlert setInformativeText:
		@"You must have write permission for the destination folder."];
	[theAlert beginSheetModalForWindow: mMainWindow
		modalDelegate: nil didEndSelector: nil contextInfo: nil];
	[theAlert release];
}

//	doDrillErrorAlert:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)doDrillErrorAlert: (NSString*)inExePath
{
	NSAlert*	theAlert		= [[NSAlert alloc] init];
	NSString*	theErrorString	= [NSString stringWithFormat:
		@"No executable file found at %@. Please locate the executable "
		"file and try again.", inExePath];

	[theAlert addButtonWithTitle: @"OK"];
	[theAlert setMessageText: @"Could not find executable file."];
	[theAlert setInformativeText: theErrorString];
	[theAlert beginSheetModalForWindow: mMainWindow
		modalDelegate: nil didEndSelector: nil contextInfo: nil];
	[theAlert release];
}

#pragma mark -
//	showPrefs
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (IBAction)showPrefs: (id)sender
{
	if (!mPrefsWindow)
	{
		printf("otx: failed to load Preferences.nib\n");
		return;
	}

	[mPrefsWindow center];
	[mPrefsWindow makeKeyAndOrderFront: nil];
}

//	switchPrefsViews:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (IBAction)switchPrefsViews: (id)sender
{
	UInt32	theNewIndex		= [sender selectedSegment];
	NSRect	targetViewFrame	= [mPrefsViews[theNewIndex] frame];

	targetViewFrame.origin	= (NSPoint){0};

	// Create dictionary for new window size.
	NSRect	origWindowFrame		= [mPrefsWindow frame];
	NSRect	targetWindowFrame	= origWindowFrame;

	targetWindowFrame.size.height	= targetViewFrame.size.height;
	targetWindowFrame				=
		[mPrefsWindow frameRectForContentRect: targetWindowFrame];

	float	windowHeightDelta	=
		targetWindowFrame.size.height - origWindowFrame.size.height;

	targetWindowFrame.origin.y	-= windowHeightDelta;

	NSMutableDictionary*	theNewWindowItem =
		[NSMutableDictionary dictionaryWithCapacity: 2];

	[theNewWindowItem setObject: mPrefsWindow
		forKey: NSViewAnimationTargetKey];
	[theNewWindowItem setObject: [NSValue valueWithBytes: &targetWindowFrame
		objCType: @encode(NSRect)] forKey: NSViewAnimationEndFrameKey];

	// Create dictionary for old view.
	NSMutableDictionary*	theOldViewItem =
		[NSMutableDictionary dictionaryWithCapacity: 2];

	[theOldViewItem setObject: mPrefsViews[mPrefsCurrentViewIndex]
		forKey: NSViewAnimationTargetKey];
	[theOldViewItem setObject: NSViewAnimationFadeOutEffect
		forKey: NSViewAnimationEffectKey];

	// Create dictionary for new view.
	NSMutableDictionary*	theNewViewItem =
		[NSMutableDictionary dictionaryWithCapacity: 2];

	[theNewViewItem setObject: mPrefsViews[theNewIndex]
		forKey: NSViewAnimationTargetKey];
	[theNewViewItem setObject: NSViewAnimationFadeInEffect
		forKey: NSViewAnimationEffectKey];

	// Create animation.
	NSViewAnimation*	theAnim = [[NSViewAnimation alloc]
		initWithViewAnimations: [NSArray arrayWithObjects:
		theOldViewItem, theNewViewItem, theNewWindowItem, nil]];

	[theAnim setDuration: 0.12];
	[theAnim setAnimationCurve: NSAnimationLinear];

	// Do the deed.
	[mPrefsViews[mPrefsCurrentViewIndex] setHidden: true];
	[theAnim startAnimation];
	[theAnim autorelease];

	mPrefsCurrentViewIndex	= theNewIndex;
}

@end
