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

/*+ (void)initialize
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
}*/

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
		[self usage];
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
	{	// We're running on a machine that doesn't exist.
		fprintf(stderr, "otx: I shouldn't be here...\n");
		[self release];
		return nil;
	}

//	NSUserDefaults*	defaults	= [NSUserDefaults standardUserDefaults];

	mOpts	= {
		SHOW_LOCAL_OFFSETS,
		ENTAB_OUTPUT,
		DONT_SHOW_DATA_SECTIONS,
		SHOW_CHECKSUM,
		SHOW_VERBOSE_MSGSENDS,
		DONT_SEPARATE_LOGICAL_BLOCKS,
		DEMANGLE_CPP_NAMES,
		SHOW_METHOD_RETURN_TYPES,
		SHOW_VARIABLE_TYPES
	};

/* 	BOOL	localOffsets			= true;		// l
 	BOOL	entabOutput				= true;		// e
 	BOOL	dataSections			= false;	// d
 	BOOL	checksum				= true;		// c
 	BOOL	verboseMsgSends			= true;		// m
 	BOOL	separateLogicalBlocks	= false;	// b
 	BOOL	demangleCPNames			= true;		// n
 	BOOL	returnTypes				= true;		// r
 	BOOL	variableTypes			= true;		// v*/

	NSString*	origFilePath	= nil;
	UInt32		i, j;

	for (i = 1; i < argc; i++)
	{
		if (argv[i][0] == '-')
		{
			if (argv[i][1] == '\0')	// just '-'
			{
				[self usage];
				[self release];
				return nil;
			}

			if (!strncmp(&argv[i][1], "arch", 5))
			{
				char*	archString	= argv[++i];

				if (!strncmp(archString, "ppc", 4))
					mArchSelector	= CPU_TYPE_POWERPC;
				else if (!strncmp(archString, "i386", 5))
					mArchSelector	= CPU_TYPE_I386;
				else
				{
					fprintf(stderr, "Unknown architecture: \"%s\"\n",
						argv[i]);
					[self usage];
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
							mOpts.localOffsets	= !mOpts.localOffsets;
							break;
						case 'e':
							mOpts.entabOutput	= !mOpts.entabOutput;
							break;
						case 'd':
							mOpts.dataSections	= !mOpts.dataSections;
							break;
						case 'c':
							mOpts.checksum	= !mOpts.checksum;
							break;
						case 'm':
							mOpts.verboseMsgSends	= !mOpts.verboseMsgSends;
							break;
						case 'b':
							mOpts.separateLogicalBlocks	=
								!mOpts.separateLogicalBlocks;
							break;
						case 'n':
							mOpts.demangleCppNames	= !mOpts.demangleCppPNames;
							break;
						case 'r':
							mOpts.returnTypes	= !mOpts.returnTypes;
							break;
						case 'v':
							mOpts.variableTypes	= !mOpts.variableTypes;
							break;
						case 'p':
							mShowProgress	= !mShowProgress;
							break;
						case 'o':
							mVerify	= !mVerify;
							break;

						default:
							fprintf(stderr, "otx: unknown argument: '%c'\n",
								argv[i][j]);
							[self usage];
							[self release];
							return nil;
					}	// switch (argv[i][j])
				}	// for (j = 1; argv[i][j] != '\0'; j++)
			}
		}
		else	// not a flag, must be the file path
		{
			origFilePath	= [NSString stringWithCString: &argv[i][0]
				encoding: NSMacOSRomanStringEncoding];
		}
	}

	if (!origFilePath)
	{
		fprintf(stderr, "You must specify an executable file to process.\n");
		[self release];
		return nil;
	}

	NSFileManager*	fileMan	= [NSFileManager defaultManager];

	// Check that the file exists.
	if (![fileMan fileExistsAtPath: origFilePath])
	{
		fprintf(stderr, "No file found at %s.\n", CSTRING(origFilePath));
		[self release];
		return nil;
	}

	// Check that the file is an executable.
	if ([[NSWorkspace sharedWorkspace] isFilePackageAtPath: origFilePath])
		[self newPackageFile: [NSURL fileURLWithPath: origFilePath]];
	else
	{
		if ([fileMan isExecutableFileAtPath: origFilePath])
			[self newOFile: [NSURL fileURLWithPath: origFilePath]
				needsPath: true];
		else
		{
			fprintf(stderr, "%s is not an executable file.\n",
				CSTRING([origFilePath lastPathComponent]));
			[self release];
			return nil;
		}
	}

	// Sanity check
	if (!mOFile)
	{
		fprintf(stderr, "Invalid file.\n");
		[self release];
		return nil;
	}

	// Check that the executable is a Mach-O file.
	NSFileHandle*	theFileH			=
		[NSFileHandle fileHandleForReadingAtPath: [mOFile path]];

	if (!theFileH)
	{
		fprintf(stderr, "Unable to open %s.\n",
			CSTRING([origFilePath lastPathComponent]));
		[self release];
		return nil;
	}

	NSData*	fileData;

	@try
	{
		fileData	= [theFileH readDataOfLength: sizeof(mArchMagic)];
	}
	@catch (NSException* e)
	{
		fprintf(stderr, "Unable to read from %s. %s\n",
			CSTRING([origFilePath lastPathComponent]),
			CSTRING([e reason]));
		[self release];
		return nil;
	}

	if ([fileData length] < sizeof(mArchMagic))
	{
		fprintf(stderr, "Truncated executable file.\n");
		[self release];
		return nil;
	}

	switch (*(UInt32*)[fileData bytes])
	{
		case MH_MAGIC:
		case MH_CIGAM:
		case FAT_MAGIC:
		case FAT_CIGAM:
			break;

		default:
			fprintf(stderr, "%s is not a Mach-O file.\n",
				CSTRING([origFilePath lastPathComponent]));
			[self release];
			return nil;
	}

/*	[defaults setBool: localOffsets forKey: ShowLocalOffsetsKey];
	[defaults setBool: entabOutput forKey: EntabOutputKey];
	[defaults setBool: dataSections forKey: ShowDataSectionKey];
	[defaults setBool: checksum forKey: ShowMD5Key];
	[defaults setBool: verboseMsgSends forKey: VerboseMsgSendsKey];
	[defaults setBool: separateLogicalBlocks forKey: SeparateLogicalBlocksKey];
	[defaults setBool: demangleCPNames forKey: DemangleCppNamesKey];
	[defaults setBool: returnTypes forKey: ShowMethodReturnTypesKey];
	[defaults setBool: variableTypes forKey: ShowIvarTypesKey];*/

	return self;
}

//	usage
// ----------------------------------------------------------------------------

- (void)usage
{
	fprintf(stderr, "Usage: "
		"otx [-ledcmbnrvpo] [-arch <arch type>] <object file>\n");
	fprintf(stderr, "\t-l    don't show local offsets\n");
	fprintf(stderr, "\t-e    don't entab output\n");
	fprintf(stderr, "\t-d    don't show data sections\n");
	fprintf(stderr, "\t-c    don't show md5 checksum\n");
	fprintf(stderr, "\t-m    don't show verbose objc_msgSend\n");
	fprintf(stderr, "\t-b    separate logical blocks\n");
	fprintf(stderr, "\t-n    don't demangle C++ symbol names\n");
	fprintf(stderr, "\t-r    don't show Obj-C method return types\n");
	fprintf(stderr, "\t-v    don't show Obj-C member variable types\n");
	fprintf(stderr, "\t-p    display progress\n");
	fprintf(stderr, "\t-o    only check the executable for obfuscation\n");
	fprintf(stderr, "\t-arch specify which architecture to process in a \n"
		"\t\tuniversal binary(ppc or i386)\n");
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

	if (mVerify)
	{
		[self verifyNops: nil];
		return;
	}

	mExeIsFat	= mArchMagic == FAT_MAGIC || mArchMagic == FAT_CIGAM;

	if ([self checkOtool] != noErr)
	{
		fprintf(stderr,
			"otx: otool was not found. Please install otool and try again.\n");
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
			fprintf(stderr, "otx: [CLIController processFile]: "
				"unknown arch type: %d", mArchSelector);
			break;
	}

	if (!procClass)
		return;

	id	theProcessor	=
		[[procClass alloc] initWithURL: mOFile controller: self
		andOpts: &mOpts];

	if (!theProcessor)
	{
		fprintf(stderr, "otx: -[CLIController processFile]: "
			"unable to create processor.\n");
		return;
	}

	ProgressState	progState	=
		{true, true, false, 0, nil, @"Loading executable"};

	[self reportProgress: &progState];

	if (![theProcessor processExe: nil])
	{
		fprintf(stderr, "otx: -[CLIController processFile]: "
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
				fprintf(stderr, "otx: -[CLIController verifyNops]: "
					"unable to create processor.\n");
				return;
			}

			unsigned char**	foundList	= nil;
			UInt32			foundCount	= 0;

			if ([theProcessor verifyNops: &foundList
				numFound: &foundCount])
			{
				printf("otx found %d broken nop's. Would you like to save "
					"a copy of the executable with fixed nop's? (y/n)\n",
					foundCount);

				char	response;

				scanf("%c", &response);

				if (response == 'y' || response == 'Y')
				{
					NopList*	theNops	= malloc(sizeof(NopList));

					theNops->list	= foundList;
					theNops->count	= foundCount;

					NSURL*	fixedFile	= [theProcessor fixNops: theNops
						toPath: [[mOFile path]
						stringByAppendingString: @"_fixed"]];

					free(theNops->list);
					free(theNops);

					if (!fixedFile)
						fprintf(stderr, "otx: unable to fix nops\n");
				}
			}
			else
			{
				printf("The executable is healthy.\n");
			}

//			[theProcessor release];

			break;
		}

		default:
			printf("Deobfuscation is only available for x86 binaries.\n");
			break;
	}
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

//	doErrorAlert
// ----------------------------------------------------------------------------

- (void)doErrorAlert
{
	fprintf(stderr, "otx: Could not create file. You must have write "
		"permission for the destination folder.\n");
}

//	doDrillErrorAlert:
// ----------------------------------------------------------------------------

- (void)doDrillErrorAlert: (NSString*)inExePath
{
	fprintf(stderr, "otx: No executable file found at %@. Please locate the "
		"executable file and try again.\n", CSTRING(inExePath));
}

#pragma mark -
//	reportProgress:
// ----------------------------------------------------------------------------

- (void)reportProgress: (ProgressState*)inState
{
	if (!mShowProgress)
		return;

	if (!inState)
	{
		fprintf(stderr, "otx: [CLIController reportProgress:] nil inState\n");
		return;
	}

	if (inState->newLine)
		fprintf(stderr, "\n");

	if (inState->description)
		fprintf(stderr, "%s", CSTRING(inState->description));

	switch (inState->refcon)
	{
		case Nudge:
		case GeneratingFile:
			fprintf(stderr, "%c", '.');

			break;

		case Complete:
			fprintf(stderr, "\n");

			break;

		default:
			break;
	}
}

@end
