/*
	CLIController.m
*/

#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <sys/types.h>
#import <sys/ptrace.h>
#import <sys/syscall.h>

#import "CLIController.h"
#import "ExeProcessor.h"
#import "PPCProcessor.h"
#import "X86Processor.h"
#import "UserDefaultKeys.h"

#import "SmartCrashReportsInstall.h"

// ============================================================================

@implementation CLIController

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
		@"YES",		ShowDataSectionKey,
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
	self = [super init];
	return self;
}

//	initWithArgs:count:
// ----------------------------------------------------------------------------

- (id)initWithArgs: (char**) argv
			 count: (SInt32) argc
{
	if (argc < 2)
	{
//		usage;
		return nil;
	}

	self = [super init];

	if (!self)
		return nil;

	// Set mArchSelector to the host architecture by default. This code was
	// lifted from http://developer.apple.com/technotes/tn/tn2086.html
	host_basic_info_data_t	hostInfo	= {0};
	mach_msg_type_number_t	infoCount	= HOST_BASIC_INFO_COUNT;

	host_info(mach_host_self(), HOST_BASIC_INFO,
		(host_info_t)&hostInfo, &infoCount);

	mArchSelector	= hostInfo.cpu_type;

	if (mArchSelector != CPU_TYPE_POWERPC	&&
		mArchSelector != CPU_TYPE_I386)
	{
		printf("otx: I shouldn't be here...\n");
		[self release];
		return nil;
	}

	BOOL	localOffsets			= true;		// l
	BOOL	entabOutput				= true;		// e
	BOOL	dataSections			= true;		// d
	BOOL	checksum				= true;		// c
	BOOL	verboseMsgSends			= true;		// m
	BOOL	separateLogicalBlocks	= false;	// b
	BOOL	demangleCPNames			= true;		// n
	BOOL	returnTypes				= true;		// r
	BOOL	variableTypes			= true;		// v

	NSString*	origFilePath	= nil;
	UInt32		i, j;

	for (i = 1; i < argc; i++)
	{
		if (argv[i][0] == '-')
		{
			if (!strncmp(&argv[i][1], "arch", 5))
			{
				char*	archString	= argv[++i];

				if (!strncmp(archString, "ppc", 4))
					mArchSelector	= CPU_TYPE_POWERPC;
				else if (!strncmp(archString, "i386", 5))
					mArchSelector	= CPU_TYPE_I386;
				else
				{
					printf("otx: unknown architecture: %s\n", argv[i]);
					[self release];
					return nil;
				}
			}
			else
			{
				for (j = 1; argv[i][j] != '\0'; j++)
				{
					switch (argv[i][j])
					{
						case 'l':
							localOffsets	= !localOffsets;
							break;
						case 'e':
							entabOutput	= !entabOutput;
							break;
						case 'd':
							dataSections	= !dataSections;
							break;
						case 'c':
							checksum	= !checksum;
							break;
						case 'm':
							verboseMsgSends	= !verboseMsgSends;
							break;
						case 'b':
							separateLogicalBlocks	= !separateLogicalBlocks;
							break;
						case 'n':
							demangleCPNames	= !demangleCPNames;
							break;
						case 'r':
							returnTypes	= !returnTypes;
							break;
						case 'v':
							variableTypes	= !variableTypes;
							break;
						case 'V':
							mVerify	= !mVerify;
							break;

						default:
							fprintf(stderr, "otx: unknown argument: '%c'\n",
								argv[i][j]);
							break;
					}	// switch (argv[i][j])
				}	// for (j = 1; argv[i][j] != '\0'; j++)
			}

			origFilePath	= [NSString stringWithCString:
				&argv[++i][0] encoding: NSMacOSRomanStringEncoding];
		}
		else	// no flags, grab the file path
		{
			origFilePath	= [NSString stringWithCString: &argv[i][0]
				encoding: NSMacOSRomanStringEncoding];
		}
	}

	if ([[NSWorkspace sharedWorkspace] isFilePackageAtPath: origFilePath])
		[self newPackageFile: [NSURL fileURLWithPath: origFilePath]];
	else
		[self newOFile: [NSURL fileURLWithPath: origFilePath] needsPath: true];

	if (mOFile)
		[mOFile retain];
	else
	{
		fprintf(stderr, "otx: invalid file\n");
		[self release];
		return nil;
	}

	NSUserDefaults*	defaults	= [NSUserDefaults standardUserDefaults];

	[defaults setBool: localOffsets forKey: ShowLocalOffsetsKey];
	[defaults setBool: entabOutput forKey: EntabOutputKey];
	[defaults setBool: dataSections forKey: ShowDataSectionKey];
	[defaults setBool: checksum forKey: ShowMD5Key];
	[defaults setBool: verboseMsgSends forKey: VerboseMsgSendsKey];
	[defaults setBool: separateLogicalBlocks forKey: SeparateLogicalBlocksKey];
	[defaults setBool: demangleCPNames forKey: DemangleCppNamesKey];
	[defaults setBool: returnTypes forKey: ShowMethodReturnTypesKey];
	[defaults setBool: variableTypes forKey: ShowIvarTypesKey];

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

	[super dealloc];
}

#pragma mark -
//	newPackageFile:
// ----------------------------------------------------------------------------
//	Attempt to drill into the package to the executable. Fails when exe name
//	is different from app name, and when the exe is unreadable.

- (void)newPackageFile: (NSURL*)inPackageFile
{
	NSString*	origPath	= [inPackageFile path];

	NSString*		theExeName	=
		[[origPath stringByDeletingPathExtension] lastPathComponent];
	NSString*		theExePath	=
	[[[origPath stringByAppendingPathComponent: @"Contents"]
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

	mExeName	= [[[inOFile path]
		stringByDeletingPathExtension] lastPathComponent];
	[mExeName retain];
}

#pragma mark -
//	processFile:
// ----------------------------------------------------------------------------

- (IBAction)processFile: (id)sender
{
	if (!mOFile)
		return;

	mExeIsFat	= mArchMagic == FAT_MAGIC || mArchMagic == FAT_CIGAM;

	if ([self checkOtool] != noErr)
	{
		printf("otx: otool not found\n");
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
			printf("otx: [CLIController processFile]: "
				"unknown arch type: %d", mArchSelector);
			break;
	}

	if (!procClass)
		return;

	id	theProcessor	=
		[[procClass alloc] initWithURL: mOFile andController: self];

	if (!theProcessor)
	{
		printf("otx: -[CLIController processFile]: "
			"unable to create processor.\n");
		return;
	}

	if (![theProcessor processExe: nil])
	{
		printf("otx: -[CLIController processFile]: "
			"possible permission error\n");
		[theProcessor release];
		return;
	}

	[theProcessor release];
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
			X86Processor*	theProcessor	=
				[[X86Processor alloc] initWithURL: mOFile andController: self];

			if (!theProcessor)
			{
				printf("otx: -[CLIController verifyNops]: "
					"unable to create processor.\n");
				return;
			}

			unsigned char**	foundList	= nil;
			UInt32			foundCount	= 0;

			if ([theProcessor verifyNops: &foundList
				numFound: &foundCount])
			{
/*				NopList*	theInfo	= malloc(sizeof(NopList));

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
					contextInfo: theInfo];*/
			}
			else
			{
/*				[theAlert addButtonWithTitle: @"OK"];
				[theAlert setMessageText: @"The executable is healthy."];
				[theAlert beginSheetModalForWindow: mMainWindow
					modalDelegate: nil didEndSelector: nil contextInfo: nil];*/
			}

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
		printf("otx: tried to fix nops with nil contextInfo\n");
		return;
	}

	NopList*	theNops	= (NopList*)contextInfo;

	if (!theNops->list)
	{
		printf("otx: tried to fix nops with nil NopList.list\n");
		free(theNops);
		return;
	}

	switch (mArchSelector)
	{
		case CPU_TYPE_I386:
		{
			X86Processor*	theProcessor	=
				[[X86Processor alloc] initWithURL: mOFile andController: self];

			if (!theProcessor)
			{
				printf("otx: -[CLIController nopAlertDidEnd]: "
					"unable to create processor.\n");
				return;
			}

			NSURL*	fixedFile	= nil;
//				[theProcessor fixNops: theNops toPath: mOutputFilePath];

			if (fixedFile)
			{
				mIgnoreArch	= true;
				[self newOFile: fixedFile needsPath: true];
			}
			else
				printf("otx: unable to fix nops\n");

			break;
		}

		default:
			break;
	}

	free(theNops->list);
	free(theNops);
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
	printf("otx: otool was not found. Please install otool and try again.");
}

//	doErrorAlert
// ----------------------------------------------------------------------------

- (void)doErrorAlert
{
	printf("otx: Could not create file. You must have write permission "
		"for the destination folder.");
}

//	doDrillErrorAlert:
// ----------------------------------------------------------------------------

- (void)doDrillErrorAlert: (NSString*)inExePath
{
	printf("No executable file found at %@. Please locate the executable "
		"file and try again.", CSTRING(inExePath));
}

#pragma mark -
//	reportProgress:
// ----------------------------------------------------------------------------

- (void)reportProgress: (ProgressState*)inState
{
	if (!inState)
	{
		printf("otx: CLIController<reportProgress:> nil inState\n");
		return;
	}

	if (inState->description)
		printf("\n%s", CSTRING(inState->description));

	switch (inState->refcon)
	{
		case Nudge:
		case GeneratingFile:
			printf("%c", '.');

			break;

		case Complete:
			printf("\n\n");

			break;

		default:
			break;
	}
}

@end
