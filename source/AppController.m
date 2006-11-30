/*
	AppController.m
*/

#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <sys/types.h>
#import <sys/ptrace.h>
#import <sys/syscall.h>

#import "AppController.h"
#import "ExeProcessor.h"
#import "PPCProcessor.h"
#import "X86Processor.h"
#import "UserDefaultKeys.h"

#import "SmartCrashReportsInstall.h"

// ============================================================================

@implementation AppController

//	initialize
// ----------------------------------------------------------------------------

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
		@"NO",		SeparateLogicalBlocksKey,
		@"NO",		ShowDataSectionKey,
		@"YES",		ShowIvarTypesKey,
		@"YES",		ShowLocalOffsetsKey,
		@"YES",		ShowMD5Key,
		@"YES",		ShowMethodReturnTypesKey,
		@"0",		UseCustomNameKey,
		@"YES",		VerboseMsgSendsKey,
		nil];

	[theController setInitialValues: theValues];
	[[theController defaults] registerDefaults: theValues];
}

//	init
// ----------------------------------------------------------------------------

- (id)init
{
	self = [super init];	// with apologies to Wil Shipley
	return self;
}

//	dealloc
// ----------------------------------------------------------------------------

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
// ----------------------------------------------------------------------------

- (void)applicationDidFinishLaunching: (NSNotification*)inNotification
{
	// Check for Smart Crash Reports.
	Boolean authRequired = false;

	if (UnsanitySCR_CanInstall(&authRequired))
		UnsanitySCR_Install(authRequired ? kUnsanitySCR_GlobalInstall : 0);

	// Set mArchSelector to the host architecture by default. This code was
	// lifted from http://developer.apple.com/technotes/tn/tn2086.html
	mach_msg_type_number_t	infoCount	= HOST_BASIC_INFO_COUNT;

	host_info(mach_host_self(), HOST_BASIC_INFO,
		(host_info_t)&mHostInfo, &infoCount);

	mArchSelector	= mHostInfo.cpu_type;

	// Setup prefs window
	UInt32	numViews	= [mPrefsViewPicker segmentCount];
	UInt32	i;

	mPrefsCurrentViewIndex	= 0;
	mPrefsViews				= calloc(numViews, sizeof(NSView*));
	mPrefsViews[0]			= mPrefsGeneralView;
	mPrefsViews[1]			= mPrefsOutputView;

	[mPrefsWindow setFrame: [mPrefsWindow frameRectForContentRect:
		[mPrefsViews[mPrefsCurrentViewIndex] frame]] display: false];

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
// ----------------------------------------------------------------------------

- (void)windowDidResize: (NSNotification*)inNotification
{
	if ([inNotification object] == mMainWindow)
		[mMainWindow display];
}

//	openExe:
// ----------------------------------------------------------------------------
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
// ----------------------------------------------------------------------------
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
// ----------------------------------------------------------------------------

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
// ----------------------------------------------------------------------------
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
// ----------------------------------------------------------------------------

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
// ----------------------------------------------------------------------------

- (IBAction)showMainWindow: (id)sender
{
	if (!mMainWindow)
	{
		fprintf(stderr, "otx: failed to load MainMenu.nib\n");
		return;
	}

	[mMainWindow makeKeyAndOrderFront: nil];
}

//	selectArch:
// ----------------------------------------------------------------------------

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
			[mVerifyButton setEnabled: false];
			break;
		case CPU_TYPE_I386:
			mOutputFileLabel	= @"_x86";
			[mVerifyButton setEnabled: true];
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
// ----------------------------------------------------------------------------

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

	ProgressState	progState	=
		{true, true, false, 0, nil, @"Loading executable"};

	[self reportProgress: &progState];

	[mProgDrawer setContentSize: [mProgDrawer maxContentSize]];
	[mProgDrawer openOnEdge: NSMinYEdge];	// Min Y = 'bottom'
}

//	thinFile:
// ----------------------------------------------------------------------------
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
			[[mOutputFilePath stringByDeletingLastPathComponent]
			stringByAppendingPathComponent:
			[mExeName stringByAppendingString:
			(mArchSelector == CPU_TYPE_POWERPC) ? @"_PPC" : @"_x86"]];
	}

	NSString*	lipoString	= [NSString stringWithFormat:
		@"lipo '%@' -output '%@' -thin %s", [mOFile path], theThinOutputPath,
		(mArchSelector == CPU_TYPE_POWERPC) ? "ppc" : "i386"];

	if (system(CSTRING(lipoString)) != 0)
		[self doLipoAlert];
}

//	verifyNops:
// ----------------------------------------------------------------------------
//	Create an instance of xxxProcessor to search for obfuscated nops. If any
//	are found, let user decide to fix them or not.

- (IBAction)verifyNops: (id)sender
{
	switch (mArchSelector)
	{
		case CPU_TYPE_I386:
		{
			ProcOptions		opts	= {0};
			X86Processor*	theProcessor	=
				[[X86Processor alloc] initWithURL: mOFile controller: self
				andOptions: &opts];

			if (!theProcessor)
			{
				fprintf(stderr, "otx: -[AppController verifyNops]: "
					"unable to create processor.\n");
				return;
			}

			unsigned char**	foundList	= nil;
			UInt32			foundCount	= 0;
			NSAlert*		theAlert	= [[NSAlert alloc] init];

			if ([theProcessor verifyNops: &foundList
				numFound: &foundCount])
			{
				NopList*	theInfo	= malloc(sizeof(NopList));

				theInfo->list	= foundList;
				theInfo->count	= foundCount;

				[theAlert addButtonWithTitle: @"Fix"];
				[theAlert addButtonWithTitle: @"Cancel"];
				[theAlert setMessageText: @"Broken nop's found."];
				[theAlert setInformativeText: [NSString stringWithFormat:
					@"otx found %d broken nop's. Would you like to save "
					@"a copy of the executable with fixed nop's?",
					foundCount]];
				[theAlert beginSheetModalForWindow: mMainWindow
					modalDelegate: self didEndSelector:
					@selector(nopAlertDidEnd:returnCode:contextInfo:)
					contextInfo: theInfo];
			}
			else
			{
				[theAlert addButtonWithTitle: @"OK"];
				[theAlert setMessageText: @"The executable is healthy."];
				[theAlert beginSheetModalForWindow: mMainWindow
					modalDelegate: nil didEndSelector: nil contextInfo: nil];
			}

			[theAlert release];
			[theProcessor release];

			break;
		}

		default:
			break;
	}
}

//	nopAlertDidEnd:returnCode:contextInfo:
// ----------------------------------------------------------------------------
//	Respond to user's decision to fix obfuscated nops.

- (void)nopAlertDidEnd: (NSAlert*)alert
			returnCode: (int)returnCode
		   contextInfo: (void*)contextInfo
{
	if (returnCode == NSAlertSecondButtonReturn)
		return;

	if (!contextInfo)
	{
		fprintf(stderr, "otx: tried to fix nops with nil contextInfo\n");
		return;
	}

	NopList*	theNops	= (NopList*)contextInfo;

	if (!theNops->list)
	{
		fprintf(stderr, "otx: tried to fix nops with nil NopList.list\n");
		free(theNops);
		return;
	}

	switch (mArchSelector)
	{
		case CPU_TYPE_I386:
		{
			ProcOptions		opts	= {0};
			X86Processor*	theProcessor	=
				[[X86Processor alloc] initWithURL: mOFile controller: self
				andOptions: &opts];

			if (!theProcessor)
			{
				fprintf(stderr, "otx: -[AppController nopAlertDidEnd]: "
					"unable to create processor.\n");
				return;
			}

			NSURL*	fixedFile	= 
				[theProcessor fixNops: theNops toPath: mOutputFilePath];

			if (fixedFile)
			{
				mIgnoreArch	= true;
				[self newOFile: fixedFile needsPath: true];
			}
			else
				fprintf(stderr, "otx: unable to fix nops\n");

			break;
		}

		default:
			break;
	}

	free(theNops->list);
	free(theNops);
}

//	validateMenuItem
// ----------------------------------------------------------------------------

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
// ----------------------------------------------------------------------------

- (void)syncSaveButton
{
	[mSaveButton setEnabled:
		(mFileIsValid && [[mOutputText stringValue] length] > 0)];
}

//	syncDescriptionText
// ----------------------------------------------------------------------------

- (void)syncDescriptionText
{
	BOOL			shouldEnableArch	= false;
	NSFileHandle*	theFileH			=
		[NSFileHandle fileHandleForReadingAtPath: [mOFile path]];

	if (!theFileH)
	{
		fprintf(stderr, "otx: -[AppController syncDescriptionText]: "
			"unable to open executable file.\n");
		return;
	}

	NSData*	theData;

	@try
	{
		theData	= [theFileH readDataOfLength: sizeof(mArchMagic)];
	}
	@catch (NSException* e)
	{
		fprintf(stderr, "otx: -[AppController syncDescriptionText]: "
			"unable to read from executable file. %s\n",
			CSTRING([e reason]));
		return;
	}

	if ([theData length] < sizeof(mArchMagic))
	{
		fprintf(stderr, "otx: -[AppController syncDescriptionText]: "
			"truncated executable file.\n");
		return;
	}

	mArchMagic		= *(UInt32*)[theData bytes];
	mFileIsValid	= true;

	[mPathText setStringValue: [mOFile path]];

	// If we just loaded a deobfuscated copy, skip the rest.
	if (mIgnoreArch)
	{
		mIgnoreArch	= false;
		return;
	}

	if (mOutputFileLabel)
	{
		[mOutputFileLabel release];
		mOutputFileLabel	= nil;
	}

	mArchSelector	= mHostInfo.cpu_type;

	switch (mArchMagic)
	{
		case MH_MAGIC:
			if (mHostInfo.cpu_type == CPU_TYPE_POWERPC)
			{
				[mTypeText setStringValue: @"PPC"];
				[mVerifyButton setEnabled: false];
			}
			else if (mHostInfo.cpu_type == CPU_TYPE_I386)
			{
				[mTypeText setStringValue: @"x86"];
				[mVerifyButton setEnabled: true];
			}

			break;

		case MH_CIGAM:
			if (mHostInfo.cpu_type == CPU_TYPE_POWERPC)
			{
				mArchSelector	= CPU_TYPE_I386;
				[mTypeText setStringValue: @"x86"];
				[mVerifyButton setEnabled: true];
			}
			else if (mHostInfo.cpu_type == CPU_TYPE_I386)
			{
				mArchSelector	= CPU_TYPE_POWERPC;
				[mTypeText setStringValue: @"PPC"];
				[mVerifyButton setEnabled: false];
			}

			break;

		case FAT_MAGIC:
		case FAT_CIGAM:
			if (mHostInfo.cpu_type == CPU_TYPE_POWERPC)
			{
				mOutputFileLabel	= @"_PPC";
				[mVerifyButton setEnabled: false];
			}
			else if (mHostInfo.cpu_type == CPU_TYPE_I386)
			{
				mOutputFileLabel	= @"_x86";
				[mVerifyButton setEnabled: true];
			}

			shouldEnableArch	= true;
			[mTypeText setStringValue: @"Fat"];
			break;

		default:
			mFileIsValid	= false;
			mArchSelector	= 0;
			[mTypeText setStringValue: @"Not a Mach-O file"];
			[mVerifyButton setEnabled: false];
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
// ----------------------------------------------------------------------------

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
// ----------------------------------------------------------------------------

- (void)drawerDidOpen: (NSNotification*)notification
{
	if ([notification object] != mProgDrawer || !mOFile)
		return;

	mExeIsFat	= mArchMagic == FAT_MAGIC || mArchMagic == FAT_CIGAM;

	if ([self checkOtool] != noErr)
	{
		fprintf(stderr, "otx: otool not found\n");
		[self doOtoolAlert];
		[mProgDrawer close];
		return;
	}

	Class	procClass	= nil;

	switch (mArchSelector)
	{
		case CPU_TYPE_POWERPC:
			procClass	= [PPCProcessor class];
			break;

		case CPU_TYPE_I386:
			procClass	= [X86Processor class];
			break;

		default:
			fprintf(stderr, "otx: [AppController drawerDidOpen]: "
				"unknown arch type: %d", mArchSelector);
			break;
	}

	if (!procClass)
	{
		[mProgDrawer close];
		return;
	}

	// Save defaults into the ProcOptions struct.
	NSUserDefaults*	theDefaults	= [NSUserDefaults standardUserDefaults];

	ProcOptions	opts	= {0};

	opts.localOffsets			=
		[theDefaults boolForKey: ShowLocalOffsetsKey];
	opts.entabOutput			=
		[theDefaults boolForKey: EntabOutputKey];
	opts.dataSections			=
		[theDefaults boolForKey: ShowDataSectionKey];
	opts.checksum				=
		[theDefaults boolForKey: ShowMD5Key];
	opts.verboseMsgSends		=
		[theDefaults boolForKey: VerboseMsgSendsKey];
	opts.separateLogicalBlocks	=
		[theDefaults boolForKey: SeparateLogicalBlocksKey];
	opts.demangleCppNames		=
		[theDefaults boolForKey: DemangleCppNamesKey];
	opts.returnTypes			=
		[theDefaults boolForKey: ShowMethodReturnTypesKey];
	opts.variableTypes			=
		[theDefaults boolForKey: ShowIvarTypesKey];

	id	theProcessor	= [[procClass alloc] initWithURL: mOFile
		controller: self andOptions: &opts];

	if (!theProcessor)
	{
		fprintf(stderr, "otx: -[AppController drawerDidOpen]: "
			"unable to create processor.\n");
		[theProcessor release];
		[mProgDrawer close];
		return;
	}

	if (![theProcessor processExe: mOutputFilePath])
	{
		fprintf(stderr, "otx: possible permission error\n");
		[self doErrorAlert];
		[theProcessor release];
		[mProgDrawer close];
		return;
	}

	[theProcessor release];
	[mProgDrawer close];

	if ([theDefaults boolForKey: OpenOutputFileKey])
		[[NSWorkspace sharedWorkspace] openFile: mOutputFilePath
			withApplication: [theDefaults objectForKey: OutputAppKey]];
}

//	drawerDidClose:
// ----------------------------------------------------------------------------

- (void)drawerDidClose: (NSNotification*)notification
{
	if ([notification object] != mProgDrawer)
		return;

	[mProgBar setIndeterminate: true];
	[mProgBar setDoubleValue: 0];
}

#pragma mark -
//	checkOtool
// ----------------------------------------------------------------------------

- (SInt32)checkOtool
{
	char*		headerArg	= mExeIsFat ? "-f" : "-h";
	NSString*	otoolString	= [NSString stringWithFormat:
		@"otool %s '%@' > /dev/null", headerArg, [mOFile path]];

	return system(CSTRING(otoolString));
}

//	doOtoolAlert
// ----------------------------------------------------------------------------

- (void)doOtoolAlert
{
	NSAlert*	theAlert	= [[NSAlert alloc] init];

	[theAlert addButtonWithTitle: @"OK"];
	[theAlert setMessageText: @"otool was not found."];
	[theAlert setInformativeText: @"Please install otool and try again."];
	[theAlert beginSheetModalForWindow: mMainWindow
		modalDelegate: nil didEndSelector: nil contextInfo: nil];
	[theAlert release];
}

//	doLipoAlert
// ----------------------------------------------------------------------------

- (void)doLipoAlert
{
	NSAlert*	theAlert	= [[NSAlert alloc] init];

	[theAlert addButtonWithTitle: @"OK"];
	[theAlert setMessageText: @"lipo was not found."];
	[theAlert setInformativeText: @"Please install lipo and try again."];
	[theAlert beginSheetModalForWindow: mMainWindow
		modalDelegate: nil didEndSelector: nil contextInfo: nil];
	[theAlert release];
}

//	doErrorAlert
// ----------------------------------------------------------------------------

- (void)doErrorAlert
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
// ----------------------------------------------------------------------------

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
// ----------------------------------------------------------------------------

- (IBAction)showPrefs: (id)sender
{
	if (!mPrefsWindow)
	{
		fprintf(stderr, "otx: failed to load Preferences.nib\n");
		return;
	}

	[mPrefsWindow center];
	[mPrefsWindow makeKeyAndOrderFront: nil];
}

//	switchPrefsViews:
// ----------------------------------------------------------------------------

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
	[theNewWindowItem setObject: [NSValue valueWithRect: targetWindowFrame]
		forKey: NSViewAnimationEndFrameKey];

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

	[theAnim setDuration: 0.14];
	[theAnim setAnimationCurve: NSAnimationLinear];

	// Do the deed.
	[mPrefsViews[mPrefsCurrentViewIndex] setHidden: true];
	[theAnim startAnimation];
	[theAnim autorelease];

	mPrefsCurrentViewIndex	= theNewIndex;
}

//	reportProgress:
// ----------------------------------------------------------------------------

- (void)reportProgress: (ProgressState*)inState
{
	if (!inState)
	{
		fprintf(stderr, "otx: AppController<reportProgress:> nil inState\n");
		return;
	}

	if (inState->description)
	{
		[mProgText setStringValue: inState->description];
		[mProgText display];
	}

	if (inState->setIndeterminate)
	{
		if (inState->indeterminate == false)
		{
			if (!inState->value)
			{
				fprintf(stderr, "otx: <reportProgress:> nil inState->value "
					"when setIndeterminate == false\n");
				return;
			}

			[mProgBar setDoubleValue: *(inState->value)];
		}

		[mProgBar setIndeterminate: inState->indeterminate];
		[mProgBar display];
	}

	switch (inState->refcon)
	{
		case Nudge:
			[mProgBar animate: self];
			[mProgBar display];

			break;

		case GeneratingFile:
			if (!inState->value)
			{
				fprintf(stderr, "otx: <reportProgress:> nil inState->value"
					"when inState->refcon == GeneratingFile\n");
				break;
			}

			[mProgBar setDoubleValue: *(inState->value)];
			[mProgBar display];

			break;

		default:
			break;
	}
}

@end
