/*
	AppController.m

	This file is in the public domain.
*/

//#import <AppKit/NSWindow.h>

#import "SystemIncludes.h"

#import "AppController.h"
#import "ExeProcessor.h"
#import "PPCProcessor.h"
#import "SmoothViewAnimation.h"
#import "SysUtils.h"
#import "UserDefaultKeys.h"
#import "X86Processor.h"

#import "ListUtils.h"

#import "SmartCrashReportsInstall.h"

#define UNIFIED_TOOLBAR_DELTA			12
#define CONTENT_BORDER_SIZE_TOP			2
#define CONTENT_BORDER_SIZE_BOTTOM		10
#define CONTENT_BORDER_MARGIN_BOTTOM	4

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
		@"NO",		EntabOutputKey,
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
		@"YES",		ShowReturnStatementsKey,
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
	return (self = [super init]);
}

//	awakeFromNib
// ----------------------------------------------------------------------------

- (void)awakeFromNib
{
/*	if (OS_IS_POST_TIGER)
	{	// Adjust main window for Leopard.
		// Save the resize masks and apply new ones.
		UInt32	origMainViewMask	= [mMainView autoresizingMask];
		UInt32	origProgViewMask	= [mProgView autoresizingMask];

		[mMainView setAutoresizingMask: NSViewMaxYMargin];
		[mProgView setAutoresizingMask: NSViewMaxYMargin];

		NSRect	curFrame	= [mMainWindow frame];
		NSSize	maxSize		= [mMainWindow contentMaxSize];
		NSSize	minSize		= [mMainWindow contentMinSize];

		curFrame.size.height	-= UNIFIED_TOOLBAR_DELTA;
		minSize.height			-= UNIFIED_TOOLBAR_DELTA;
		maxSize.height			-= UNIFIED_TOOLBAR_DELTA;

		[mMainWindow setContentMinSize: minSize];
		[mMainWindow setFrame: curFrame display: false];
		[mMainWindow setContentMaxSize: maxSize];

		[mMainView setAutoresizingMask: origMainViewMask];
		[mProgView setAutoresizingMask: origProgViewMask];

		// Set up smaller gradients.
		[mMainWindow setAutorecalculatesContentBorderThickness: false
													   forEdge: NSMaxYEdge];
		[mMainWindow setAutorecalculatesContentBorderThickness: false
													   forEdge: NSMinYEdge];
		[mMainWindow setContentBorderThickness: CONTENT_BORDER_SIZE_TOP
									   forEdge: NSMaxYEdge];
		[mMainWindow setContentBorderThickness: CONTENT_BORDER_SIZE_BOTTOM
									   forEdge: NSMinYEdge];

		// Set up text shadows.
	}
	else
	{
		NSImage*	bgImage	= [NSImage imageNamed: @"Main Window Background"];

		[mMainWindow setBackgroundColor:
			[NSColor colorWithPatternImage: bgImage]];
	}*/
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

	if (mPolishedLightColor)
		[mPolishedLightColor release];

	if (mPolishedDarkColor)
		[mPolishedDarkColor release];

	if (mTextShadow)
		[mTextShadow release];

	if (mPrefsViews)
		free(mPrefsViews);

	[super dealloc];
}

#pragma mark -
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

//	newPackageFile:
// ----------------------------------------------------------------------------
//	Attempt to drill into the package to the executable. Fails when the exe is
//	unreadable.

- (void)newPackageFile: (NSURL*)inPackageFile
{
	if (mOutputFilePath)
		[mOutputFilePath release];

	mOutputFilePath	= [inPackageFile path];
	[mOutputFilePath retain];

	NSBundle*	exeBundle	= [NSBundle bundleWithPath: mOutputFilePath];

	if (!exeBundle)
	{
		fprintf(stderr, "otx: [AppController newPackageFile:] "
			"unable to get bundle from path: %s\n", UTF8STRING(mOutputFilePath));
		return;
	}

	NSString*	theExePath	= [exeBundle executablePath];

	if (!theExePath)
	{
		fprintf(stderr, "otx: [AppController newPackageFile:] "
			"unable to get executable path from bundle: %s\n",
			UTF8STRING(mOutputFilePath));
		return;
	}

	[self newOFile: [NSURL fileURLWithPath: theExePath] needsPath: false];
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

	if ([[NSWorkspace sharedWorkspace] isFilePackageAtPath: mOutputFilePath])
		mExeName	= [[mOutputFilePath lastPathComponent]
			stringByDeletingPathExtension];
	else
		mExeName	= [mOutputFilePath lastPathComponent];

	[mExeName retain];

	[self syncDescriptionText];
	[self syncOutputText: nil];
	[self syncSaveButton];
}

#pragma mark -
//	setupMainWindow
// ----------------------------------------------------------------------------

- (void)setupMainWindow
{
	if (OS_IS_POST_TIGER)
	{	// Adjust main window for Leopard.
		// Save the resize masks and apply new ones.
		UInt32	origMainViewMask	= [mMainView autoresizingMask];
		UInt32	origProgViewMask	= [mProgView autoresizingMask];

		[mMainView setAutoresizingMask: NSViewMaxYMargin];
		[mProgView setAutoresizingMask: NSViewMaxYMargin];

		NSRect	curFrame	= [mMainWindow frame];
		NSSize	maxSize		= [mMainWindow contentMaxSize];
		NSSize	minSize		= [mMainWindow contentMinSize];

		curFrame.size.height	-= UNIFIED_TOOLBAR_DELTA;
		minSize.height			-= UNIFIED_TOOLBAR_DELTA - CONTENT_BORDER_MARGIN_BOTTOM;
		maxSize.height			-= UNIFIED_TOOLBAR_DELTA - CONTENT_BORDER_MARGIN_BOTTOM;

		[mMainWindow setContentMinSize: minSize];
		[mMainWindow setFrame: curFrame
					  display: true];
		[mMainWindow setContentMaxSize: maxSize];

		// Grow the prog view for the gradient.
		[mMainView setAutoresizingMask: NSViewMinYMargin | NSViewNotSizable];
		[mProgView setAutoresizingMask: NSViewHeightSizable | NSViewMaxYMargin];

		curFrame.size.height += CONTENT_BORDER_MARGIN_BOTTOM;
		[mMainWindow setFrame: curFrame
					  display: true];

		[mMainView setAutoresizingMask: origMainViewMask];
		[mProgView setAutoresizingMask: origProgViewMask];

		// Set up smaller gradients.
		[mMainWindow setAutorecalculatesContentBorderThickness: false
													   forEdge: NSMaxYEdge];
		[mMainWindow setAutorecalculatesContentBorderThickness: false
													   forEdge: NSMinYEdge];
		[mMainWindow setContentBorderThickness: CONTENT_BORDER_SIZE_TOP
									   forEdge: NSMaxYEdge];
		[mMainWindow setContentBorderThickness: CONTENT_BORDER_SIZE_BOTTOM
									   forEdge: NSMinYEdge];

		// Set up text shadows.
		[[mPathText cell] setBackgroundStyle: NSBackgroundStyleRaised];
		[[mPathLabelText cell] setBackgroundStyle: NSBackgroundStyleRaised];
		[[mTypeText cell] setBackgroundStyle: NSBackgroundStyleRaised];
		[[mTypeLabelText cell] setBackgroundStyle: NSBackgroundStyleRaised];
		[[mOutputLabelText cell] setBackgroundStyle: NSBackgroundStyleRaised];
		[[mProgText cell] setBackgroundStyle: NSBackgroundStyleRaised];
	}
	else
	{
		NSImage*	bgImage	= [NSImage imageNamed: @"Main Window Background"];

		[mMainWindow setBackgroundColor:
		 [NSColor colorWithPatternImage: bgImage]];

		// Set up text shadows.
		[self applyShadowToText: mPathLabelText];
		[self applyShadowToText: mTypeLabelText];
		[self applyShadowToText: mOutputLabelText];
	}

	// At this point, the window is still brushed metal. We can get away with
	// not setting the background image here because hiding the prog view
	// resizes the window, which results in our delegate saving the day.
	[self hideProgView: false openFile: false];

	[mMainWindow setFrameAutosaveName: [mMainWindow title]];
}

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

//	applyShadowToText:
// ----------------------------------------------------------------------------

- (void)applyShadowToText: (NSTextField*)inText
{
	if (OS_IS_TIGER)	// not needed on Leopard
	{
		NSMutableAttributedString*	newString	=
			[[NSMutableAttributedString alloc] initWithAttributedString:
			[inText attributedStringValue]];

		[newString addAttribute: NSShadowAttributeName value: mTextShadow
			range: NSMakeRange(0, [newString length])];
		[inText setAttributedStringValue: newString];
		[newString release];
	}
}

#pragma mark -
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

//	attemptToProcessFile:
// ----------------------------------------------------------------------------

- (IBAction)attemptToProcessFile: (id)sender
{
	if (!mOFile)
	{
		fprintf(stderr, "otx: [AppController attemptToProcessFile]: "
			"tried to process nil object file.\n");
		return;
	}

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

	// Check if the output file exists.
	if ([[NSFileManager defaultManager] fileExistsAtPath: mOutputFilePath])
	{
		NSString*	fileName	= [mOutputFilePath lastPathComponent];
		NSString*	folderName	=
			[[mOutputFilePath stringByDeletingLastPathComponent]
			lastPathComponent];
		NSAlert*	alert		= [[NSAlert alloc] init];

		[alert addButtonWithTitle: @"Replace"];
		[alert addButtonWithTitle: @"Cancel"];
		[alert setMessageText: [NSString stringWithFormat:
			@"\"%@\" already exists. Do you want to replace it?", fileName]];
		[alert setInformativeText:
			[NSString stringWithFormat: @"A file or folder"
			@" with the same name already exists in %@."
			@" Replacing it will overwrite its current contents.", folderName]];
		[alert beginSheetModalForWindow: mMainWindow
			modalDelegate: self
			didEndSelector: @selector(dupeFileAlertDidEnd:returnCode:contextInfo:)
			contextInfo: nil];
	}
	else
	{
		[self processFile];
	}
}

//	processFile
// ----------------------------------------------------------------------------

- (void)processFile
{
	NSDictionary*	progDict	= [[NSDictionary alloc] initWithObjectsAndKeys:
		[NSNumber numberWithBool: true], PRIndeterminateKey,
		[NSNumber numberWithBool: true], PRAnimateKey,
		@"Loading executable", PRDescriptionKey,
		nil];

	[self reportProgress: progDict];
	[progDict release];

	if ([self checkOtool: [mOFile path]] != noErr)
	{
		[self reportError: @"otool was not found."
		       suggestion: @"Please install otool and try again."];
		return;
	}

	mProcessing	= true;
	[self adjustInterfaceForMultiThread];
	[self showProgView];
}

//	continueProcessingFile
// ----------------------------------------------------------------------------

- (void)continueProcessingFile
{
	NSAutoreleasePool*	pool		= [[NSAutoreleasePool alloc] init];
	Class				procClass	= nil;

	switch (mArchSelector)
	{
		case CPU_TYPE_POWERPC:
			procClass	= [PPCProcessor class];
			break;

		case CPU_TYPE_I386:
			procClass	= [X86Processor class];
			break;

		default:
			fprintf(stderr, "otx: [AppController continueProcessingFile]: "
				"unknown arch type: %d", mArchSelector);
			break;
	}

	if (!procClass)
	{
		[pool release];
		return;
	}

	// Save defaults into the ProcOptions struct.
	NSUserDefaults*	theDefaults	= [NSUserDefaults standardUserDefaults];
	ProcOptions		opts		= {0};

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
	opts.returnStatements		=
		[theDefaults boolForKey: ShowReturnStatementsKey];

	id	theProcessor	= [[procClass alloc] initWithURL: mOFile
		controller: self options: &opts];

	if (!theProcessor)
	{
		fprintf(stderr, "otx: -[AppController continueProcessingFile]: "
			"unable to create processor.\n");
		[theProcessor release];
		[self performSelectorOnMainThread:
			@selector(processingThreadDidFinish:)
			withObject: [NSNumber numberWithBool: false]
			waitUntilDone: false];

		[pool release];
		return;
	}

	if (![theProcessor processExe: mOutputFilePath])
	{
		fprintf(stderr, "otx: -[AppController continueProcessingFile]: "
			"unable to process %s.\n", UTF8STRING([mOFile path]));
		[theProcessor release];
		[self performSelectorOnMainThread:
			@selector(processingThreadDidFinish:)
			withObject: [NSNumber numberWithBool: false]
			waitUntilDone: false];

		[pool release];
		return;
	}

	[theProcessor release];
	[self performSelectorOnMainThread:
		@selector(processingThreadDidFinish:)
		withObject: [NSNumber numberWithBool: true]
		waitUntilDone: false];

	[pool release];
}

//	processingThreadDidFinish:
// ----------------------------------------------------------------------------

- (void)processingThreadDidFinish: (NSNumber*)successfully
{
	mProcessing	= false;

	if ([successfully boolValue])
	{
		[self hideProgView: true openFile:
			[[NSUserDefaults standardUserDefaults]
			boolForKey: OpenOutputFileKey]];
	}
	else
	{
		[self hideProgView: true openFile: false];
		[self reportError: @"Could not create file."
		       suggestion: @"You must have write permission for the "
		                    "destination folder."];
	}
}


#pragma mark -
//	adjustInterfaceForMultiThread
// ----------------------------------------------------------------------------
//	In future, we may allow the user to do more than twiddle prefs and resize
//	the window. For now, just disable the fun stuff.

- (void)adjustInterfaceForMultiThread
{
	[self syncSaveButton];

	[mArchPopup setEnabled: false];
	[mThinButton setEnabled: false];
	[mVerifyButton setEnabled: false];
	[mOutputText setEnabled: false];
	[[mMainWindow standardWindowButton: NSWindowCloseButton]
		setEnabled: false];

	[mMainWindow display];
}

//	adjustInterfaceForSingleThread
// ----------------------------------------------------------------------------

- (void)adjustInterfaceForSingleThread
{
	[self syncSaveButton];

	[mArchPopup setEnabled: mExeIsFat];
	[mThinButton setEnabled: mExeIsFat];
	[mVerifyButton setEnabled: (mArchSelector == CPU_TYPE_I386)];
	[mOutputText setEnabled: true];
	[[mMainWindow standardWindowButton: NSWindowCloseButton]
		setEnabled: true];

	[mMainWindow display];
}

#pragma mark -
//	showProgView
// ----------------------------------------------------------------------------

- (void)showProgView
{
	// Set up the target window frame.
	NSRect	targetWindowFrame	= [mMainWindow frame];
	NSRect	progViewFrame		= [mProgView frame];

	targetWindowFrame.origin.y		-= progViewFrame.size.height;
	targetWindowFrame.size.height	+= progViewFrame.size.height;

	// Save the resize masks and apply new ones.
	UInt32	origMainViewMask	= [mMainView autoresizingMask];
	UInt32	origProgViewMask	= [mProgView autoresizingMask];

	[mMainView setAutoresizingMask: NSViewMinYMargin];
	[mProgView setAutoresizingMask: NSViewMinYMargin];

	// Set up an animation.
	NSMutableDictionary*	newWindowItem =
		[NSMutableDictionary dictionaryWithCapacity: 8];

	// Standard keys
	[newWindowItem setObject: mMainWindow
		forKey: NSViewAnimationTargetKey];
	[newWindowItem setObject: [NSValue valueWithRect: targetWindowFrame]
		forKey: NSViewAnimationEndFrameKey];

	NSNumber*	effect			= [NSNumber numberWithUnsignedInt:
		(NSXViewAnimationUpdateResizeMasksAtEndEffect		|
		NSXViewAnimationUpdateWindowMinMaxSizesAtEndEffect	|
		NSXViewAnimationPerformSelectorAtEndEffect)];
	NSNumber*	origMainMask	= [NSNumber numberWithUnsignedInt:
		origMainViewMask];
	NSNumber*	origProgMask	= [NSNumber numberWithUnsignedInt:
		origProgViewMask];

	// Custom keys
	[newWindowItem setObject: effect
		forKey: NSXViewAnimationCustomEffectsKey];
	[newWindowItem setObject: [NSArray arrayWithObjects:
		origMainMask, origProgMask, nil]
		forKey: NSXViewAnimationResizeMasksArrayKey];
	[newWindowItem setObject: [NSArray arrayWithObjects:
		mMainView, mProgView, nil]
		forKey: NSXViewAnimationResizeViewsArrayKey];

	// Since we're about to grow the window, first adjust the max height.
	NSSize	maxSize	= [mMainWindow contentMaxSize];
	NSSize	minSize	= [mMainWindow contentMinSize];

	maxSize.height	+= progViewFrame.size.height;
	minSize.height	+= progViewFrame.size.height;

	[mMainWindow setContentMaxSize: maxSize];

	// Set the min size after the animation completes.
	NSValue*	minSizeValue	= [NSValue valueWithSize: minSize];

	[newWindowItem setObject: minSizeValue
		forKey: NSXViewAnimationWindowMinSizeKey];

	// Continue processing after the animation completes.
	SEL	continueSel	= @selector(continueProcessingFile);

	[newWindowItem setObject:
		[NSValue value: &continueSel withObjCType: @encode(SEL)]
		forKey: NSXViewAnimationSelectorKey];
	[newWindowItem setObject: [NSNumber numberWithBool: true]
		forKey: NSXViewAnimationPerformInNewThreadKey];

	SmoothViewAnimation*	theAnim	= [[SmoothViewAnimation alloc]
		initWithViewAnimations: [NSArray arrayWithObjects:
		newWindowItem, nil]];

	[theAnim setDelegate: self];
	[theAnim setDuration: kMainAnimationTime];
	[theAnim setAnimationCurve: NSAnimationLinear];

	// Do the deed.
	[theAnim startAnimation];
	[theAnim autorelease];
}

//	hideProgView:
// ----------------------------------------------------------------------------

- (void)hideProgView: (BOOL)inAnimate
			openFile: (BOOL)inOpenFile
{
	NSRect	targetWindowFrame	= [mMainWindow frame];
	NSRect	progViewFrame		= [mProgView frame];

	targetWindowFrame.origin.y		+= progViewFrame.size.height;
	targetWindowFrame.size.height	-= progViewFrame.size.height;

	UInt32	origMainViewMask	= [mMainView autoresizingMask];
	UInt32	origProgViewMask	= [mProgView autoresizingMask];

	NSNumber*	origMainMask	= [NSNumber numberWithUnsignedInt:
		origMainViewMask];
	NSNumber*	origProgMask	= [NSNumber numberWithUnsignedInt:
		origProgViewMask];

	[mMainView setAutoresizingMask: NSViewMinYMargin];
	[mProgView setAutoresizingMask: NSViewMinYMargin];

	NSSize	maxSize	= [mMainWindow contentMaxSize];
	NSSize	minSize	= [mMainWindow contentMinSize];

	maxSize.height	-= progViewFrame.size.height;
	minSize.height	-= progViewFrame.size.height;

	[mMainWindow setContentMinSize: minSize];

	if (inAnimate)
	{
		NSMutableDictionary*	newWindowItem =
			[NSMutableDictionary dictionaryWithCapacity: 10];

		[newWindowItem setObject: mMainWindow
			forKey: NSViewAnimationTargetKey];
		[newWindowItem setObject: [NSValue valueWithRect: targetWindowFrame]
			forKey: NSViewAnimationEndFrameKey];

		UInt32	effects	=
			NSXViewAnimationUpdateResizeMasksAtEndEffect		|
			NSXViewAnimationUpdateWindowMinMaxSizesAtEndEffect	|
			NSXViewAnimationPerformSelectorAtEndEffect;

		if (inOpenFile)
		{
			effects	|= NSXViewAnimationOpenFileWithAppAtEndEffect;
			[newWindowItem setObject: mOutputFilePath
				forKey: NSXViewAnimationFilePathKey];
			[newWindowItem setObject: [[NSUserDefaults standardUserDefaults]
				objectForKey: OutputAppKey]
				forKey: NSXViewAnimationAppNameKey];
		}

		// Custom keys
		[newWindowItem setObject:[NSNumber numberWithUnsignedInt: effects]
			forKey: NSXViewAnimationCustomEffectsKey];
		[newWindowItem setObject: [NSArray arrayWithObjects:
			origMainMask, origProgMask, nil]
			forKey: NSXViewAnimationResizeMasksArrayKey];
		[newWindowItem setObject: [NSArray arrayWithObjects:
			mMainView, mProgView, nil]
			forKey: NSXViewAnimationResizeViewsArrayKey];

		SEL	adjustSel	= @selector(adjustInterfaceForSingleThread);

		[newWindowItem setObject:
			[NSValue value: &adjustSel withObjCType: @encode(SEL)]
			forKey: NSXViewAnimationSelectorKey];

		NSValue*	maxSizeValue	=
			[NSValue valueWithSize: maxSize];

		[newWindowItem setObject: maxSizeValue
			forKey: NSXViewAnimationWindowMaxSizeKey];

		SmoothViewAnimation*	theAnim	= [[SmoothViewAnimation alloc]
			initWithViewAnimations: [NSArray arrayWithObjects:
			newWindowItem, nil]];

		[theAnim setDelegate: self];
		[theAnim setDuration: kMainAnimationTime];
		[theAnim setAnimationCurve: NSAnimationLinear];

		// Do the deed.
		[theAnim startAnimation];
		[theAnim autorelease];
	}
	else
	{
		[mMainWindow setFrame: targetWindowFrame display: false];
		[mMainWindow setContentMaxSize: maxSize];
		[mMainView setAutoresizingMask: origMainViewMask];
		[mProgView setAutoresizingMask: origProgViewMask];
	}	
}

#pragma mark -
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
		@"lipo \"%@\" -output \"%@\" -thin %s", [mOFile path], theThinOutputPath,
		(mArchSelector == CPU_TYPE_POWERPC) ? "ppc" : "i386"];
    
	if (system(UTF8STRING(lipoString)) != 0)
		[self reportError: @"lipo was not found."
		       suggestion: @"Please install lipo and try again."];
}

#pragma mark -
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
				options: &opts];

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
				[theAlert setMessageText: @"No broken nop's."];
				[theAlert setInformativeText: @"The executable is healthy."];
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
				options: &opts];

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

//	validateMenuItem:
// ----------------------------------------------------------------------------

- (BOOL)validateMenuItem: (NSMenuItem*)menuItem
{
	if ([menuItem action] == @selector(attemptToProcessFile:))
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


//	dupeFileAlertDidEnd:returnCode:contextInfo:
// ----------------------------------------------------------------------------

#pragma mark -
- (void)dupeFileAlertDidEnd: (NSAlert*)alert
				 returnCode: (int)returnCode
				contextInfo: (void*)contextInfo
{
	if (returnCode == NSAlertSecondButtonReturn)
		return;

	[self processFile];
}

#pragma mark -
//	syncSaveButton
// ----------------------------------------------------------------------------

- (void)syncSaveButton
{
	[mSaveButton setEnabled: (mFileIsValid &&
		[[mOutputText stringValue] length] > 0) && !mProcessing];
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
			UTF8STRING([e reason]));
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
	[self applyShadowToText: mPathText];

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

	NSString*	tempString;

	mExeIsFat	= false;

	switch (mArchMagic)
	{
		case MH_MAGIC:
			if (mHostInfo.cpu_type == CPU_TYPE_POWERPC)
			{
				tempString	= @"PPC";
				[mVerifyButton setEnabled: false];
			}
			else if (mHostInfo.cpu_type == CPU_TYPE_I386)
			{
				tempString	= @"x86";
				[mVerifyButton setEnabled: true];
			}

			break;

		case MH_CIGAM:
			if (mHostInfo.cpu_type == CPU_TYPE_POWERPC)
			{
				mArchSelector	= CPU_TYPE_I386;
				tempString		= @"x86";
				[mVerifyButton setEnabled: true];
			}
			else if (mHostInfo.cpu_type == CPU_TYPE_I386)
			{
				mArchSelector	= CPU_TYPE_POWERPC;
				tempString		= @"PPC";
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

			mExeIsFat			= true;
			shouldEnableArch	= true;
			tempString			= @"Fat";
			break;

		default:
			mFileIsValid	= false;
			mArchSelector	= 0;
			tempString		= @"Not a Mach-O file";
			[mVerifyButton setEnabled: false];
			break;
	}

	[mTypeText setStringValue: tempString];
	[self applyShadowToText: mTypeText];

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
	if (!mFileIsValid || mProcessing)
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
//	setupPrefsWindow
// ----------------------------------------------------------------------------

- (void)setupPrefsWindow
{
	// Setup toolbar.
	NSToolbar*	toolbar = [[[NSToolbar alloc]
		initWithIdentifier: OTXPrefsToolbarID] autorelease];

	[toolbar setDisplayMode: NSToolbarDisplayModeIconAndLabel];
    [toolbar setDelegate: self];

    [mPrefsWindow setToolbar: toolbar];
	[mPrefsWindow setShowsToolbarButton: false];

	// Load views.
	UInt32	numViews	= [[toolbar items] count];
	UInt32	i;

	mPrefsViews		= calloc(numViews, sizeof(NSView*));
	mPrefsViews[0]	= mPrefsGeneralView;
	mPrefsViews[1]	= mPrefsOutputView;

	// Set the General panel as selected.
	[toolbar setSelectedItemIdentifier: PrefsGeneralToolbarItemID];

	// Set window size.
	// Maybe it's just me, but when I have to tell an object something by
	// first asking the object something, I always think there's an instance
	// method missing.
	[mPrefsWindow setFrame: [mPrefsWindow frameRectForContentRect:
		[mPrefsViews[mPrefsCurrentViewIndex] frame]] display: false];

	for (i = 0; i < numViews; i++)
		[[mPrefsWindow contentView] addSubview: mPrefsViews[i]];
}

//	showPrefs
// ----------------------------------------------------------------------------

- (IBAction)showPrefs: (id)sender
{
	// Set window position only if the window is not already onscreen.
	if (![mPrefsWindow isVisible])
		[mPrefsWindow center];

	[mPrefsWindow makeKeyAndOrderFront: nil];
}

//	switchPrefsViews:
// ----------------------------------------------------------------------------

- (IBAction)switchPrefsViews: (id)sender
{
	NSToolbarItem*	item		= (NSToolbarItem*)sender;
	UInt32			newIndex	= [item tag];

	if (newIndex == mPrefsCurrentViewIndex)
		return;

	NSRect	targetViewFrame	= [mPrefsViews[newIndex] frame];

	// Calculate the new window size.
	NSRect	origWindowFrame		= [mPrefsWindow frame];
	NSRect	targetWindowFrame	= origWindowFrame;

	targetWindowFrame.size.height	= targetViewFrame.size.height;
	targetWindowFrame				=
		[mPrefsWindow frameRectForContentRect: targetWindowFrame];

	float	windowHeightDelta	=
		targetWindowFrame.size.height - origWindowFrame.size.height;

	targetWindowFrame.origin.y	-= windowHeightDelta;

	// Create dictionary for new window size.
	NSMutableDictionary*	newWindowItem =
		[NSMutableDictionary dictionaryWithCapacity: 5];

	[newWindowItem setObject: mPrefsWindow
		forKey: NSViewAnimationTargetKey];
	[newWindowItem setObject: [NSValue valueWithRect: targetWindowFrame]
		forKey: NSViewAnimationEndFrameKey];

	[newWindowItem setObject: [NSNumber numberWithUnsignedInt:
		NSXViewAnimationSwapAtBeginningAndEndEffect]
		forKey: NSXViewAnimationCustomEffectsKey];
	[newWindowItem setObject: mPrefsViews[mPrefsCurrentViewIndex]
		forKey: NSXViewAnimationSwapOldKey];
	[newWindowItem setObject: mPrefsViews[newIndex]
		forKey: NSXViewAnimationSwapNewKey];

	// Create animation.
	SmoothViewAnimation*	windowAnim	= [[SmoothViewAnimation alloc]
		initWithViewAnimations: [NSArray arrayWithObject:
		newWindowItem]];

	[windowAnim setDelegate: self];
	[windowAnim setDuration: kPrefsAnimationTime];
	[windowAnim setAnimationCurve: NSAnimationLinear];

	mPrefsCurrentViewIndex	= newIndex;

	// Do the deed.
	[windowAnim startAnimation];
	[windowAnim autorelease];
}

#pragma mark -
#pragma mark ErrorReporter protocol
//	reportError:suggestion:
// ----------------------------------------------------------------------------

- (void)reportError: (NSString*)inMessageText
		 suggestion: (NSString*)inInformativeText
{
	NSAlert*	theAlert	= [[NSAlert alloc] init];

	[theAlert addButtonWithTitle: @"OK"];
	[theAlert setMessageText: inMessageText];
	[theAlert setInformativeText: inInformativeText];
	[theAlert beginSheetModalForWindow: mMainWindow
		modalDelegate: nil didEndSelector: nil contextInfo: nil];
	[theAlert release];
}

#pragma mark -
#pragma mark ProgressReporter protocol
//	reportProgress:
// ----------------------------------------------------------------------------

- (void)reportProgress: (NSDictionary*)inDict
{
	if (!inDict)
	{
		fprintf(stderr, "otx: [AppController reportProgress:] nil inDict\n");
		return;
	}

	NSString*	description		= [inDict objectForKey: PRDescriptionKey];
	NSNumber*	indeterminate	= [inDict objectForKey: PRIndeterminateKey];
	NSNumber*	value			= [inDict objectForKey: PRValueKey];
	NSNumber*	animate			= [inDict objectForKey: PRAnimateKey];

	if (description)
	{
		[mProgText setStringValue: description];
		[self applyShadowToText: mProgText];
	}

	if (value)
		[mProgBar setDoubleValue: [value doubleValue]];

	if (indeterminate)
		[mProgBar setIndeterminate: [indeterminate boolValue]];

	if (animate && [animate boolValue])
		[mProgBar animate: self];

	// This is a workaround for the bug mentioned by Mike Ash here:
	// http://mikeash.com/blog/pivot/entry.php?id=25 In our case, it causes
	// the progress bar to freeze when processing more than once per launch.
	// In other words, the first time you process an exe, everything is fine.
	// Subsequent processing of any exe displays a retarded progress bar.
	NSEvent*	pingUI	= [NSEvent otherEventWithType: NSApplicationDefined
		location: NSMakePoint(0, 0) modifierFlags: 0 timestamp: 0
		windowNumber: 0 context: nil subtype: 0 data1: 0 data2: 0];

	[[NSApplication sharedApplication] postEvent: pingUI atStart: false];
}

#pragma mark -
#pragma mark DropBox delegates
//	dropBox:dragDidEnter:
// ----------------------------------------------------------------------------

- (NSDragOperation)dropBox: (DropBox*)inDropBox
			  dragDidEnter: (id <NSDraggingInfo>)inItem
{
	if (inDropBox != mDropBox || mProcessing)
		return false;

	NSPasteboard*	pasteBoard	= [inItem draggingPasteboard];

	// Bail if not a file.
	if (![[pasteBoard types] containsObject: NSFilenamesPboardType])
		return NSDragOperationNone;

	NSArray*	files	= [pasteBoard
		propertyListForType: NSFilenamesPboardType];

	// Bail if not a single file.
	if ([files count] != 1)
		return NSDragOperationNone;

	NSDragOperation	sourceDragMask	= [inItem draggingSourceOperationMask];

	// Bail if modifier keys pressed.
	if (!(sourceDragMask & NSDragOperationLink))
		return NSDragOperationNone;

	return NSDragOperationLink;
}

//	dropBox:didReceiveItem:
// ----------------------------------------------------------------------------

- (BOOL)dropBox: (DropBox*)inDropBox
 didReceiveItem: (id<NSDraggingInfo>)inItem
{
	if (inDropBox != mDropBox || mProcessing)
		return false;

	NSURL*	theURL	= [NSURL URLFromPasteboard: [inItem draggingPasteboard]];

	if (!theURL)
		return false;

	if ([[NSWorkspace sharedWorkspace] isFilePackageAtPath: [theURL path]])
		[self newPackageFile: theURL];
	else
		[self newOFile: theURL needsPath: true];

	return true;
}

#pragma mark -
#pragma mark NSAnimation delegates
//	animationShouldStart:
// ----------------------------------------------------------------------------
//	We're only hooking this to perform custom effects with NSViewAnimations,
//	not to determine whether to start the animation. For this reason, we
//	always return true, even if a sanity check fails.

- (BOOL)animationShouldStart: (NSAnimation*)animation
{
	if (![animation isKindOfClass: [NSViewAnimation class]])
		return true;

	NSArray*	animatedViews	= [(NSViewAnimation*)animation viewAnimations];

	if (!animatedViews)
		return true;

	NSWindow*	animatingWindow	= [[animatedViews objectAtIndex: 0]
		objectForKey: NSViewAnimationTargetKey];

	if (animatingWindow != mMainWindow	&&
		animatingWindow != mPrefsWindow)
		return true;

	UInt32	i;
	UInt32	numAnimations	= [animatedViews count];
	id		animObject		= nil;

	for (i = 0; i < numAnimations; i++)
	{
		animObject	= [animatedViews objectAtIndex: i];

		if (!animObject)
			continue;

		NSNumber*	effectsNumber	=
			[animObject objectForKey: NSXViewAnimationCustomEffectsKey];

		if (!effectsNumber)
			continue;

		UInt32	effects	= [effectsNumber unsignedIntValue];

		if (effects & NSXViewAnimationSwapAtBeginningEffect)
		{	// Hide/show 2 views.
			NSView*	oldView	= [animObject
				objectForKey: NSXViewAnimationSwapOldKey];
			NSView*	newView	= [animObject
				objectForKey: NSXViewAnimationSwapNewKey];

			if (oldView)
				[oldView setHidden: true];

			if (newView)
				[newView setHidden: false];
		}
		else if (effects & NSXViewAnimationSwapAtBeginningAndEndEffect)
		{	// Hide a view.
			NSView*	oldView	= [animObject
				objectForKey: NSXViewAnimationSwapOldKey];

			if (oldView)
				[oldView setHidden: true];
		}
	}

	return true;
}

//	animationDidEnd:
// ----------------------------------------------------------------------------

- (void)animationDidEnd: (NSAnimation*)animation
{
	if (![animation isKindOfClass: [NSViewAnimation class]])
		return;

	NSArray*	animatedViews	= [(NSViewAnimation*)animation viewAnimations];

	if (!animatedViews)
		return;

	NSWindow*	animatingWindow	= [[animatedViews objectAtIndex: 0]
		objectForKey: NSViewAnimationTargetKey];

	if (animatingWindow != mMainWindow	&&
		animatingWindow != mPrefsWindow)
		return;

	UInt32	i;
	UInt32	numAnimations	= [animatedViews count];
	id		animObject		= nil;

	for (i = 0; i < numAnimations; i++)
	{
		animObject	= [animatedViews objectAtIndex: i];

		if (!animObject)
			continue;

		NSNumber*	effectsNumber	=
			[animObject objectForKey: NSXViewAnimationCustomEffectsKey];

		if (!effectsNumber)
			continue;

		UInt32	effects	= [effectsNumber unsignedIntValue];

		if (effects & NSXViewAnimationSwapAtEndEffect)
		{	// Hide/show 2 views.
			NSView*	oldView	= [animObject
				objectForKey: NSXViewAnimationSwapOldKey];
			NSView*	newView	= [animObject
				objectForKey: NSXViewAnimationSwapNewKey];

			if (oldView)
				[oldView setHidden: true];

			if (newView)
				[newView setHidden: false];
		}
		else if (effects & NSXViewAnimationSwapAtBeginningAndEndEffect)
		{	// Show a view.
			NSView*	newView	= [animObject
				objectForKey: NSXViewAnimationSwapNewKey];

			if (newView)
				[newView setHidden: false];
		}

		// Adjust multiple views' resize masks.
		if (effects & NSXViewAnimationUpdateResizeMasksAtEndEffect)
		{
			NSArray*	masks	= [animObject
				objectForKey: NSXViewAnimationResizeMasksArrayKey];
			NSArray*	views	= [animObject
				objectForKey: NSXViewAnimationResizeViewsArrayKey];

			if (!masks || !views)
				continue;

			NSView*		view;
			NSNumber*	mask;
			UInt32		i;
			UInt32		numMasks	= [masks count];
			UInt32		numViews	= [views count];

			if (numMasks != numViews)
				continue;

			for (i = 0; i < numMasks; i++)
			{
				mask	= [masks objectAtIndex: i];
				view	= [views objectAtIndex: i];

				if (!mask || !view)
					continue;

				[view setAutoresizingMask: [mask unsignedIntValue]];
			}
		}

		// Update the window's min and/or max sizes.
		if (effects & NSXViewAnimationUpdateWindowMinMaxSizesAtEndEffect)
		{
			NSValue*	minSizeValue	= [animObject objectForKey:
				NSXViewAnimationWindowMinSizeKey];
			NSValue*	maxSizeValue	= [animObject objectForKey:
				NSXViewAnimationWindowMaxSizeKey];

			if (minSizeValue)
				[animatingWindow setContentMinSize:
					[minSizeValue sizeValue]];

			if (maxSizeValue)
				[animatingWindow setContentMaxSize:
					[maxSizeValue sizeValue]];
		}

		// Perform a selector. The method's return value is ignored, and the
		// method must take no arguments. For any other kind of method, use
		// NSInvocation instead.
		if (effects & NSXViewAnimationPerformSelectorAtEndEffect)
		{
			NSValue*	selValue	= [animObject objectForKey:
				NSXViewAnimationSelectorKey];

			if (selValue)
			{
				SEL	theSel;

				[selValue getValue: &theSel];

				NSNumber*	newThread	= [animObject objectForKey:
					NSXViewAnimationPerformInNewThreadKey];

				if (newThread)
					[NSThread detachNewThreadSelector: theSel
						toTarget: self withObject: nil];
				else
					[self performSelector: theSel];
			}
		}

		// Open a file in another application.
		if (effects & NSXViewAnimationOpenFileWithAppAtEndEffect)
		{
			NSString*	filePath	= [animObject objectForKey:
				NSXViewAnimationFilePathKey];
			NSString*	appName		= [animObject objectForKey:
				NSXViewAnimationAppNameKey];

			if (filePath && appName)
				[[NSWorkspace sharedWorkspace] openFile: filePath
					withApplication: appName];
		}
	}
}

#pragma mark -
#pragma mark NSApplication delegates
//	applicationWillFinishLaunching:
// ----------------------------------------------------------------------------

- (void)applicationWillFinishLaunching: (NSNotification*)inNotification
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

	if (mArchSelector != CPU_TYPE_POWERPC	&&
		mArchSelector != CPU_TYPE_I386)
	{	// We're running on a machine that doesn't exist.
		fprintf(stderr, "otx: I shouldn't be here...\n");
	}

	// Setup our text shadow ivar.
	mTextShadow	= [[NSShadow alloc] init];

	[mTextShadow setShadowColor: [NSColor
		colorWithCalibratedRed: 1.0 green: 1.0 blue: 1.0 alpha: 0.5]];
	[mTextShadow setShadowOffset: NSMakeSize(0.0, -1.0)];
	[mTextShadow setShadowBlurRadius: 0.0];

	// Setup the windows.
	[self setupPrefsWindow];
	[self setupMainWindow];

	// Show the main window.
	[mMainWindow center];
	[mMainWindow makeKeyAndOrderFront: nil];
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

//	applicationShouldTerminateAfterLastWindowClosed:
// ----------------------------------------------------------------------------

- (BOOL)applicationShouldTerminateAfterLastWindowClosed: (NSApplication*)inApp
{
	return true;
}

#pragma mark -
#pragma mark NSControl delegates
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

#pragma mark -
#pragma mark NSToolbar delegates
//	toolbar:itemForItemIdentifier:willBeInsertedIntoToolbar:
// ----------------------------------------------------------------------------

- (NSToolbarItem*)toolbar: (NSToolbar*)toolbar
	itemForItemIdentifier: (NSString*)itemIdent
willBeInsertedIntoToolbar: (BOOL)willBeInserted
{
	NSToolbarItem*	item = [[[NSToolbarItem alloc]
		initWithItemIdentifier: itemIdent] autorelease];

	if ([itemIdent isEqual: PrefsGeneralToolbarItemID])
	{
		[item setLabel: @"General"];
		[item setImage: [NSImage imageNamed: @"Prefs General Icon"]];
		[item setTarget: self];
		[item setAction: @selector(switchPrefsViews:)];
		[item setTag: 0];
	}
	else if ([itemIdent isEqual: PrefsOutputToolbarItemID])
	{
		[item setLabel: @"Output"];
		[item setImage: [NSImage imageNamed: @"Prefs Output Icon"]];
		[item setTarget: self];
		[item setAction: @selector(switchPrefsViews:)];
		[item setTag: 1];
	}
	else
		item = nil;

	return item;
}

//	toolbarDefaultItemIdentifiers:
// ----------------------------------------------------------------------------

- (NSArray*)toolbarDefaultItemIdentifiers: (NSToolbar*)toolbar
{
	return PrefsToolbarItemsArray;
}

//	toolbarAllowedItemIdentifiers:
// ----------------------------------------------------------------------------

- (NSArray*)toolbarAllowedItemIdentifiers: (NSToolbar*)toolbar
{
	return PrefsToolbarItemsArray;
}

//	toolbarSelectableItemIdentifiers:
// ----------------------------------------------------------------------------

- (NSArray*)toolbarSelectableItemIdentifiers: (NSToolbar*)toolbar
{
	return PrefsToolbarItemsArray;
}

//	validateToolbarItem:
// ----------------------------------------------------------------------------

- (BOOL)validateToolbarItem: (NSToolbarItem*)toolbarItem
{
	return true;
}

#pragma mark -
#pragma mark NSWindow delegates
//	windowDidResize:
// ----------------------------------------------------------------------------
//	Implemented to avoid artifacts from the NSBox.

- (void)windowDidResize: (NSNotification*)inNotification
{
	if ([inNotification object] == mMainWindow)
		[mMainWindow display];
}

@end
