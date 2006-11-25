/*
	ExeProcessor.m

	This file relies upon, and steals code from, the cctools source code
	available from: http://www.opensource.apple.com/darwinsource/
*/

#import "SystemIncludes.h"

#import "demangle.h"

#import "ExeProcessor.h"
#import "ListUtils.h"
#import "ObjectLoader.h"
#import "UserDefaultKeys.h"

// ============================================================================

@implementation ExeProcessor

// ExeProcessor is a base class that handles processor-independent issues.
// PPCProcessor and X86Processor are subclasses that add functionality
// specific to those CPUs. The AppController class creates a new instance of
// one of those subclasses class for each processing, and deletes the
// instance as soon as possible. Member variables may or may not be
// re-initialized before destruction. Do not reuse a single instance of
// those subclasses for multiple processings.

//	initWithURL:andController:
// ----------------------------------------------------------------------------

- (id)initWithURL: (NSURL*)inURL
	andController: (id)inController
{
	if (!inURL || !inController)
		return nil;

	if ((self = [super init]) == nil)
		return nil;

	mController				= inController;
	mOFile					= inURL;
	mCurrentFuncInfoIndex	= -1;

	// Load exe into RAM.
	NSError*	theError	= nil;
	NSData*		theData		= [NSData dataWithContentsOfURL: mOFile
		options: 0 error: &theError];

	if (!theData)
	{
		fprintf(stderr, "otx: error loading executable from disk: %s\n",
			CSTRING([theError localizedFailureReason]));
		[self release];
		return nil;
	}

	mRAMFileSize	= [theData length];

	if (mRAMFileSize < sizeof(mArchMagic))
	{
		fprintf(stderr, "otx: truncated executable file\n");
		[theData release];
		[self release];
		return nil;
	}

	mRAMFile	= malloc(mRAMFileSize);

	if (!mRAMFile)
	{
		fprintf(stderr, "otx: not enough memory to allocate mRAMFile\n");
		[theData release];
		[self release];
		return nil;
	}

	[theData getBytes: mRAMFile];

	mArchMagic	= *(UInt32*)mRAMFile;
	mExeIsFat	= mArchMagic == FAT_MAGIC || mArchMagic == FAT_CIGAM;

	[self speedyDelivery];

	return self;
}

//	dealloc
// ----------------------------------------------------------------------------

- (void)dealloc
{
	if (mRAMFile)
		free(mRAMFile);

	if (mFuncSyms)
		free(mFuncSyms);

	if (mObjcSects)
		free(mObjcSects);

	if (mClassMethodInfos)
		free(mClassMethodInfos);

	if (mCatMethodInfos)
		free(mCatMethodInfos);

	if (mThunks)
		free(mThunks);

	[self deleteFuncInfos];
	[self deleteLinesFromList: mPlainLineListHead];
	[self deleteLinesFromList: mVerboseLineListHead];

	[super dealloc];
}

//	deleteFuncInfos
// ----------------------------------------------------------------------------

- (void)deleteFuncInfos
{
	if (!mFuncInfos)
		return;

	UInt32			i;
	UInt32			j;
	FunctionInfo*	funcInfo;
	BlockInfo*		blockInfo;

	for (i = 0; i < mNumFuncInfos; i++)
	{
		funcInfo	= &mFuncInfos[i];

		if (funcInfo->blocks)
		{
			for (j = 0; j < funcInfo->numBlocks; j++)
			{
				blockInfo	= &funcInfo->blocks[j];

				if (blockInfo->state.regInfos)
				{
					free(blockInfo->state.regInfos);
					blockInfo->state.regInfos	= nil;
				}

				if (blockInfo->state.localSelves)
				{
					free(blockInfo->state.localSelves);
					blockInfo->state.localSelves	= nil;
				}
			}

			free(funcInfo->blocks);
			funcInfo->blocks	= nil;
		}
	}

	free(mFuncInfos);
	mFuncInfos	= nil;
}

//	processExe:arch:
// ----------------------------------------------------------------------------

- (BOOL)processExe: (NSString*)inOutputFilePath
{
	if (!mArchMagic)
	{
		fprintf(stderr, "otx: tried to process non-machO file\n");
		return false;
	}

	mOutputFilePath	= inOutputFilePath;
	mMachHeader		= nil;

	// Save some prefs for speed.
	NSUserDefaults*	theDefaults	= [NSUserDefaults standardUserDefaults];

	mDemangleCppNames		= [theDefaults boolForKey: DemangleCppNamesKey];
	mEntabOutput			= [theDefaults boolForKey: EntabOutputKey];
	mSeparateLogicalBlocks	= [theDefaults boolForKey: SeparateLogicalBlocksKey];
	mShowDataSection		= [theDefaults boolForKey: ShowDataSectionKey];
	mShowIvarTypes			= [theDefaults boolForKey: ShowIvarTypesKey];
	mShowLocalOffsets		= [theDefaults boolForKey: ShowLocalOffsetsKey];
	mShowMethReturnTypes	= [theDefaults boolForKey: ShowMethodReturnTypesKey];
	mVerboseMsgSends		= [theDefaults boolForKey: VerboseMsgSendsKey];

	if (![self loadMachHeader])
	{
		fprintf(stderr, "otx: failed to load mach header\n");
		return false;
	}

	[self loadLCommands];

	ProgressState	progState	= {false, false, 0, nil, @"Calling otool"};

	[mController reportProgress: &progState];

	// Create temp files.
	NSURL*	theVerboseFile	= nil;
	NSURL*	thePlainFile	= nil;

	[self createVerboseFile: &theVerboseFile andPlainFile: &thePlainFile];

	if (!theVerboseFile || !thePlainFile)
	{
		fprintf(stderr, "otx: could not create temp files\n");
		return false;
	}

	// Get the party started.
	if (![self processVerboseFile: theVerboseFile andPlainFile: thePlainFile])
	{
		fprintf(stderr, "otx: unable to process temp files\n");
		return false;
	}

	// Delete temp files.
	NSFileManager*	theFileMan	= [NSFileManager defaultManager];

	[theFileMan removeFileAtPath: [theVerboseFile path] handler: nil];
	[theFileMan removeFileAtPath: [thePlainFile path] handler: nil];

	return true;
}

//	createVerboseFile:andPlainFile:
// ----------------------------------------------------------------------------
//	Call otool on the exe too many times.

- (void)createVerboseFile: (NSURL**)outVerbosePath
			 andPlainFile: (NSURL**)outPlainPath
{
	NSString*		oPath			= [mOFile path];
	NSString*		otoolString;
	char			cmdString[100]	= {0};
	char*			cmdFormatString	= mExeIsFat ? "otool -arch %s" : "otool";
	NSProcessInfo*	procInfo		= [NSProcessInfo processInfo];

	snprintf(cmdString, MAX_ARCH_STRING_LENGTH + 1,
		cmdFormatString, mArchString);

	NSString*	verbosePath	= [NSTemporaryDirectory()
		stringByAppendingPathComponent:
		[NSString stringWithFormat: @"temp_%@.otx",
		[procInfo globallyUniqueString]]];
	NSString*	plainPath	= [NSTemporaryDirectory()
		stringByAppendingPathComponent:
		[NSString stringWithFormat: @"temp_%@.otx",
		[procInfo globallyUniqueString]]];

	// The following lines call otool twice for each section we want, once
	// with verbosity, once without. sed removes the 1st line from sections
	// other than the first text section, which is a redundant filepath.
	// The first system call creates or overwrites the file at verbosePath,
	// subsequent calls append to the file. The order in which sections are
	// printed may not reflect their order in the executable.

	ProgressState	progState	=
		{false, false, Nudge, nil, nil};	// wink wink, say no more...

	[mController reportProgress: &progState];

	// Create verbose temp file.
	otoolString	= [NSString stringWithFormat:
		@"%s -V -s __TEXT __text '%@' > '%@'",
		cmdString, oPath, verbosePath];

	if (system(CSTRING(otoolString)) != noErr)
		return;

	[mController reportProgress: &progState];

	// Create non-verbose temp file.
	otoolString	= [NSString stringWithFormat:
		@"%s -v -s __TEXT __text '%@' > '%@'",
		cmdString, oPath, plainPath];
	system(CSTRING(otoolString));

	[mController reportProgress: &progState];

	// Append to verbose temp file.
	otoolString	= [NSString stringWithFormat:
		@"%s -V -s __TEXT __coalesced_text '%@' | sed '1 d' >> '%@'",
		cmdString, oPath, verbosePath];
	system(CSTRING(otoolString));

	[mController reportProgress: &progState];

	// Append to non-verbose temp file.
	otoolString	= [NSString stringWithFormat:
		@"%s -v -s __TEXT __coalesced_text '%@' | sed '1 d' >> '%@'",
		cmdString, oPath, plainPath];
	system(CSTRING(otoolString));

	[mController reportProgress: &progState];

	// Append to verbose temp file.
	otoolString	= [NSString stringWithFormat:
		@"%s -V -s __TEXT __textcoal_nt '%@' | sed '1 d' >> '%@'",
		cmdString, oPath, verbosePath];
	system(CSTRING(otoolString));

	[mController reportProgress: &progState];

	// Append to non-verbose temp file.
	otoolString	= [NSString stringWithFormat:
		@"%s -v -s __TEXT __textcoal_nt '%@' | sed '1 d' >> '%@'",
		cmdString, oPath, plainPath];
	system(CSTRING(otoolString));

	*outVerbosePath	= [NSURL fileURLWithPath: verbosePath];
	*outPlainPath	= [NSURL fileURLWithPath: plainPath];
}

#pragma mark -
//	processVerboseFile:andPlainFile:
// ----------------------------------------------------------------------------

- (BOOL)processVerboseFile: (NSURL*)inVerboseFile
			  andPlainFile: (NSURL*)inPlainFile
{
	// Load otool's outputs into parallel doubly-linked lists of C strings.
	// List heads have nil 'prev'. List tails have nil 'next'.
	const char*	verbosePath	= CSTRING([inVerboseFile path]);
	const char*	plainPath	= CSTRING([inPlainFile path]);

	FILE*	verboseFile	= fopen(verbosePath, "r");

	if (!verboseFile)
	{
		perror("otx: unable to open verbose temp file");
		return false;
	}

	FILE*	plainFile	= fopen(plainPath, "r");

	if (!plainFile)
	{
		perror("otx: unable to open plain temp file");
		return false;
	}

	char	theVerboseCLine[MAX_LINE_LENGTH];
	char	thePlainCLine[MAX_LINE_LENGTH];
	Line*	thePrevVerboseLine	= nil;
	Line*	thePrevPlainLine	= nil;
	SInt32	theFileError;

	// Loop thru lines in the temp files.
	while (!feof(verboseFile) && !feof(plainFile))
	{
		bzero(theVerboseCLine, MAX_LINE_LENGTH);
		bzero(thePlainCLine, MAX_LINE_LENGTH);

		if (!fgets(theVerboseCLine, MAX_LINE_LENGTH, verboseFile))
		{
			theFileError	= ferror(verboseFile);

			if (theFileError)
				fprintf(stderr, "otx: error reading from verbose temp file: %d\n",
					theFileError);

			break;
		}

		if (!fgets(thePlainCLine, MAX_LINE_LENGTH, plainFile))
		{
			theFileError	= ferror(plainFile);

			if (theFileError)
				fprintf(stderr, "otx: error reading from plain temp file: %d\n",
					theFileError);

			break;
		}

		Line*	theVerboseLine	= malloc(sizeof(Line));
		Line*	thePlainLine	= malloc(sizeof(Line));

		bzero(theVerboseLine, sizeof(Line));
		bzero(thePlainLine, sizeof(Line));
		theVerboseLine->length	= strlen(theVerboseCLine);
		thePlainLine->length	= strlen(thePlainCLine);
		theVerboseLine->chars	= malloc(theVerboseLine->length + 1);
		thePlainLine->chars		= malloc(thePlainLine->length + 1);
		strncpy(theVerboseLine->chars, theVerboseCLine,
			theVerboseLine->length + 1);
		strncpy(thePlainLine->chars, thePlainCLine,
			thePlainLine->length + 1);

		// Connect the plain and verbose lines.
		theVerboseLine->alt	= thePlainLine;
		thePlainLine->alt	= theVerboseLine;

		// Add the lines to the lists.
		InsertLineAfter(theVerboseLine, thePrevVerboseLine,
			&mVerboseLineListHead);
		InsertLineAfter(thePlainLine, thePrevPlainLine,
			&mPlainLineListHead);

		thePrevVerboseLine	= theVerboseLine;
		thePrevPlainLine	= thePlainLine;
		mNumLines++;
	}

	if (fclose(verboseFile) != 0)
	{
		perror("otx: unable to close verbose temp file");
		return false;
	}

	if (fclose(plainFile) != 0)
	{
		perror("otx: unable to close plain temp file");
		return false;
	}

	// Optionally insert md5.
	if ([[NSUserDefaults standardUserDefaults] boolForKey: ShowMD5Key])
		[self insertMD5];

	ProgressState	progState	= {false, false, 0, nil, @"Gathering info"};

	[mController reportProgress: &progState];

	// Gather info about lines while they're virgin.
	[self gatherLineInfos];

	// Gather info about logical blocks. The second pass applies info
	// for backward branches.
	[self gatherFuncInfos];
	[self gatherFuncInfos];

	UInt32	progCounter	= 0;
	double	progValue	= 0.0;

	progState	= (ProgressState)
		{true, false, GeneratingFile, &progValue, @"Generating file"};

	[mController reportProgress: &progState];

	Line*	theLine	= mPlainLineListHead;

	// Loop thru lines.
	while (theLine)
	{
		if (!(progCounter % PROGRESS_FREQ))
		{
			progValue	= (double)progCounter / mNumLines * 100;
			progState	= (ProgressState)
				{false, false, GeneratingFile, &progValue, nil};

			[mController reportProgress: &progState];
		}

		if (theLine->info.isCode)
		{
			ProcessCodeLine(&theLine);

			if (mEntabOutput)
				EntabLine(theLine);
		}
		else
			ProcessLine(theLine);

		theLine	= theLine->next;
		progCounter++;
	}

//	progState	= (ProgressState){true, true, 0, nil, @"Writing file"};
	progState	= (ProgressState){false, false, Complete, nil, nil};

	[mController reportProgress: &progState];

	// Create output file.
	if (![self printLinesFromList: mPlainLineListHead])
		return false;

	if (mShowDataSection)
	{
		if (![self printDataSections])
			return false;
	}

	return true;
}

//	gatherLineInfos
// ----------------------------------------------------------------------------
//	To make life easier as we make changes to the lines, whatever info we need
//	is harvested early here.

- (void)gatherLineInfos
{
	Line*	theLine		= mPlainLineListHead;
	UInt32	progCounter	= 0;

	while (theLine)
	{
		if (!(progCounter % (PROGRESS_FREQ * 3)))
		{
			ProgressState	progState	=
				{false, false, Nudge, nil, nil};

			[mController reportProgress: &progState];
		}

		if (LineIsCode(theLine->chars))
		{
			theLine->info.isCode		=
			theLine->alt->info.isCode	= true;
			theLine->info.address		=
			theLine->alt->info.address	= AddressFromLine(theLine->chars);

			CodeFromLine(theLine);

			strncpy(theLine->alt->info.code, theLine->info.code,
				strlen(theLine->info.code) + 1);

			theLine->info.isFunction		=
			theLine->alt->info.isFunction	= LineIsFunction(theLine);

			CheckThunk(theLine);

			if (theLine->info.isFunction)
			{
				mNumFuncInfos++;

				if (mFuncInfos)
					mFuncInfos	= realloc(mFuncInfos,
						sizeof(FunctionInfo) * mNumFuncInfos);
				else
					mFuncInfos	= malloc(sizeof(FunctionInfo));

				mFuncInfos[mNumFuncInfos - 1]	= (FunctionInfo)
					{theLine->info.address, nil, 0};
			}
		}
		else	// not code...
		{
			if (strstr(theLine->chars,
				"Contents of (__TEXT,__coalesced_text)"))
				mEndOfText	= mCoalTextSect.s.addr + mCoalTextSect.s.size;
			else if (strstr(theLine->chars,
				"Contents of (__TEXT,__textcoal_nt)"))
				mEndOfText	= mCoalTextNTSect.s.addr + mCoalTextNTSect.s.size;
		}

		theLine	= theLine->next;
		progCounter++;
	}

	mEndOfText	= mTextSect.s.addr + mTextSect.s.size;
}

//	gatherFuncInfos
// ----------------------------------------------------------------------------
//	Subclasses may override

- (void)gatherFuncInfos
{}

//	processLine:
// ----------------------------------------------------------------------------

- (void)processLine: (Line*)ioLine;
{
	if (!strlen(ioLine->chars))
		return;

	char*	theSearchString			= "Contents of ";
	UInt8	theSearchStringLength	= strlen(theSearchString);

	if (strstr(ioLine->chars, theSearchString))
	{
		char	theTempLine[MAX_LINE_LENGTH]	= {0};

		theTempLine[0]	= '\n';

		strncat(theTempLine, &ioLine->chars[theSearchStringLength],
			strlen(&ioLine->chars[theSearchStringLength]));

		ioLine->length	= strlen(theTempLine);
		strncpy(ioLine->chars, theTempLine, ioLine->length + 1);

		if (strstr(ioLine->chars, "\n(__TEXT,__coalesced_text)"))
		{
			mEndOfText		= mCoalTextSect.s.addr + mCoalTextSect.s.size;
			mLocalOffset	= 0;
		}
		else if (strstr(ioLine->chars, "\n(__TEXT,__textcoal_nt)"))
		{
			mEndOfText		= mCoalTextNTSect.s.addr + mCoalTextNTSect.s.size;
			mLocalOffset	= 0;
		}
	}
	else if (mDemangleCppNames)
	{
		char*	demString	=
			PrepareNameForDemangling(ioLine->chars);

		if (demString)
		{
			char*	cpName	= cplus_demangle(demString, DEMANGLE_OPTS);

			free(demString);

			if (cpName)
			{
				if (strlen(cpName) < MAX_LINE_LENGTH - 1)
				{
					free(ioLine->chars);
					ioLine->length	= strlen(cpName) + 1;

					// cpName is null-terminated but has no '\n'. Allocate
					// space for both.
					ioLine->chars	= malloc(ioLine->length + 2);

					// copy cpName and terminate it.
					strncpy(ioLine->chars, cpName, ioLine->length + 1);

					// add '\n' and terminate it.
					strncat(ioLine->chars, "\n", 1);
				}

				free(cpName);
			}
		}
	}
}

//	processCodeLine:
// ----------------------------------------------------------------------------

- (void)processCodeLine: (Line**)ioLine;
{
	if (!ioLine || !(*ioLine) || !((*ioLine)->chars))
	{
		fprintf(stderr, "otx: tried to process nil code line\n");
		return;
	}

	ChooseLine(ioLine);

	UInt32	theOrigLength								= (*ioLine)->length;
	char	addrSpaces[MAX_FIELD_SPACING]				= {0};
	char	instSpaces[MAX_FIELD_SPACING]				= {0};
	char	mnemSpaces[MAX_FIELD_SPACING]				= {0};
	char	opSpaces[MAX_FIELD_SPACING]					= {0};
	char	commentSpaces[MAX_FIELD_SPACING]			= {0};
	char	localOffsetString[9]						= {0};
	char	theAddressCString[9]						= {0};
	char	theMnemonicCString[20]						= {0};
	char	theOrigCommentCString[MAX_COMMENT_LENGTH]	= {0};
	char	theCommentCString[MAX_COMMENT_LENGTH]		= {0};

	// Swap in saved registers if necessary
	BOOL	needNewLine	= [self restoreRegisters: (*ioLine)];

	mLineOperandsCString[0]	= 0;

	char*	origFormatString	= "%s\t%s\t%s%n";
	UInt32	consumedAfterOp		= 0;

	// The address and mnemonic always exist, separated by a tab.
	sscanf((*ioLine)->chars, origFormatString, theAddressCString,
		theMnemonicCString, mLineOperandsCString, &consumedAfterOp);

	// If we didn't grab everything up to the newline, there's a comment
	// remaining. Copy it, starting after the preceding tab.
	if (consumedAfterOp && consumedAfterOp < theOrigLength - 1)
		strncpy(theOrigCommentCString, (*ioLine)->chars + consumedAfterOp + 1,
			theOrigLength - consumedAfterOp - 2);

	char*	theCodeCString	= (*ioLine)->info.code;
	SInt16	i				=
		mFieldWidths.instruction - strlen(theCodeCString);

	for (; i > 1; i--)
		mnemSpaces[i - 2]	= 0x20;

	i	= mFieldWidths.mnemonic - strlen(theMnemonicCString);

	for (; i > 1; i--)
		opSpaces[i - 2]	= 0x20;

	// Fill up commentSpaces based on operands field width.
	if (mLineOperandsCString[0] && theOrigCommentCString[0])
	{
		i	= mFieldWidths.operands - strlen(mLineOperandsCString);

		for (; i > 1; i--)
			commentSpaces[i - 2]	= 0x20;
	}

	// Remove "; symbol stub for: "
	if (theOrigCommentCString[0])
	{
		char*	theSubstring	=
			strstr(theOrigCommentCString, "; symbol stub for: ");

		if (theSubstring)
			strncpy(theCommentCString, &theOrigCommentCString[19],
				strlen(&theOrigCommentCString[19]) + 1);
		else
			strncpy(theCommentCString, theOrigCommentCString,
				strlen(theOrigCommentCString) + 1);
	}

	char	theMethCName[1000]	= {0};

	// Check if this is the beginning of a function.
	if ((*ioLine)->info.isFunction)
	{
		// Squash the new block flag, just in case.
		mEnteringNewBlock	= false;

		// New function, new local offset count and current func.
		mLocalOffset	= 0;
		mCurrentFuncPtr	= (*ioLine)->info.address;

		// Try to build the method name.
		MethodInfo*	theInfo			=
			ObjcMethodFromAddress(mCurrentFuncPtr);

		if (theInfo != nil)
		{
			char*	className	= nil;
			char*	catName		= nil;

			if (theInfo->oc_cat.category_name)
			{
				className	= GetPointer(
					(UInt32)theInfo->oc_cat.class_name, nil);
				catName		= GetPointer(
					(UInt32)theInfo->oc_cat.category_name, nil);
			}
			else if (theInfo->oc_class.name)
			{
				className	= GetPointer(
					(UInt32)theInfo->oc_class.name, nil);
			}

			if (className)
			{
				char*	selName	= GetPointer(
					(UInt32)theInfo->m.method_name, nil);

				if (selName)
				{
					if (!theInfo->m.method_types)
						return;

					char	returnCType[MAX_TYPE_STRING_LENGTH]	= {0};
					char*	methTypes	=
						GetPointer((UInt32)theInfo->m.method_types, nil);

					if (!methTypes)
						return;

					[self decodeMethodReturnType: methTypes
						output: returnCType];

					if (catName)
					{
						char*	methNameFormat	= mShowMethReturnTypes ?
							"\n%1$c(%5$s)[%2$s(%3$s) %4$s]\n" :
							"\n%c[%s(%s) %s]\n";

						snprintf(theMethCName, 1000,
							methNameFormat,
							(theInfo->inst) ? '-' : '+',
							className, catName, selName, returnCType);
					}
					else
					{
						char*	methNameFormat	= mShowMethReturnTypes ?
							"\n%1$c(%4$s)[%2$s %3$s]\n" : "\n%c[%s %s]\n";

						snprintf(theMethCName, 1000,
							methNameFormat,
							(theInfo->inst) ? '-' : '+',
							className, selName, returnCType);
					}
				}
			}
		}	// if (theInfo != nil)

		// Add or replace the method name if possible, else add '\n'.
		if ((*ioLine)->prev && (*ioLine)->prev->info.isCode)	// prev line is code
		{
			if (theMethCName[0])
			{
				Line*	theNewLine	= malloc(sizeof(Line));

				theNewLine->length	= strlen(theMethCName);
				theNewLine->chars	= malloc(theNewLine->length + 1);

				strncpy(theNewLine->chars, theMethCName,
					theNewLine->length + 1);
				InsertLineBefore(theNewLine, *ioLine, &mPlainLineListHead);
			}
			else if ((*ioLine)->info.address == mAddrDyldStubBindingHelper)
			{
				Line*	theNewLine	= malloc(sizeof(Line));
				char*	theDyldName	= "\ndyld_stub_binding_helper:\n";

				theNewLine->length	= strlen(theDyldName);
				theNewLine->chars	= malloc(theNewLine->length + 1);

				strncpy(theNewLine->chars, theDyldName, theNewLine->length + 1);
				InsertLineBefore(theNewLine, *ioLine, &mPlainLineListHead);
			}
			else if ((*ioLine)->info.address == mAddrDyldFuncLookupPointer)
			{
				Line*	theNewLine	= malloc(sizeof(Line));
				char*	theDyldName	= "\n__dyld_func_lookup:\n";

				theNewLine->length	= strlen(theDyldName);
				theNewLine->chars	= malloc(theNewLine->length + 1);

				strncpy(theNewLine->chars, theDyldName, theNewLine->length + 1);
				InsertLineBefore(theNewLine, *ioLine, &mPlainLineListHead);
			}
			else
				needNewLine	= true;
		}
		else	// prev line is not code
		{
			if (theMethCName[0])
			{
				Line*	theNewLine	= malloc(sizeof(Line));

				theNewLine->length	= strlen(theMethCName);
				theNewLine->chars	= malloc(theNewLine->length + 1);

				strncpy(theNewLine->chars, theMethCName,
					theNewLine->length + 1);
				ReplaceLine((*ioLine)->prev, theNewLine, &mPlainLineListHead);
			}
			else	// theMethName sux, add '\n' to otool's method name.
			{
				char	theNewLine[MAX_LINE_LENGTH]	= {0};

				theNewLine[0]	= '\n';

				strncat(theNewLine, (*ioLine)->prev->chars,
					(*ioLine)->prev->length);
				free((*ioLine)->prev->chars);
				(*ioLine)->prev->length	= strlen(theNewLine);
				(*ioLine)->prev->chars	= malloc((*ioLine)->prev->length + 1);
				strncpy((*ioLine)->prev->chars, theNewLine,
					(*ioLine)->prev->length + 1);
			}
		}

		ResetRegisters((*ioLine));

	}	// if ((*ioLine)->info.isFunction)

	// Find a comment if necessary.
	if (!theCommentCString[0])
	{
		CommentForLine(*ioLine);

		UInt32	origCommentLength	= strlen(mLineCommentCString);

		if (origCommentLength)
		{
			char	tempComment[MAX_COMMENT_LENGTH]	= {0};
			UInt32	i, j= 0;

			for (i = 0; i < origCommentLength; i++)
			{
				if (mLineCommentCString[i] == '\n')
				{
					tempComment[j++]	= '\\';
					tempComment[j++]	= 'n';
				}
				else if (mLineCommentCString[i] == '\r')
				{
					tempComment[j++]	= '\\';
					tempComment[j++]	= 'r';
				}
				else if (mLineCommentCString[i] == '\t')
				{
					tempComment[j++]	= '\\';
					tempComment[j++]	= 't';
				}
				else
					tempComment[j++]	= mLineCommentCString[i];
			}

			if (mLineOperandsCString[0])
				strncpy(theCommentCString, tempComment,
					strlen(tempComment) + 1);
			else
				strncpy(mLineOperandsCString, tempComment,
					strlen(tempComment) + 1);

			// Fill up commentSpaces based on operands field width.
			SInt32	k	= mFieldWidths.operands - strlen(mLineOperandsCString);

			for (; k > 1; k--)
				commentSpaces[k - 2]	= 0x20;
		}
	}	// if (!theCommentCString[0])
	else	// otool gave us a comment.
	{	// Optionally modify otool's comment.
		if (mVerboseMsgSends)
			CommentForMsgSendFromLine(theCommentCString, *ioLine);

		// Check whether we should trample r3/eax.
		char*	selString	= SelectorForMsgSend(theCommentCString, *ioLine);

		mReturnValueIsKnown	= SelectorIsFriendly(selString);
	}

	// Demangle operands if necessary.
	if (mLineOperandsCString[0] && mDemangleCppNames)
	{
		char*	demString	=
			PrepareNameForDemangling(mLineOperandsCString);

		if (demString)
		{
			char*	cpName	= cplus_demangle(demString, DEMANGLE_OPTS);

			free(demString);

			if (cpName)
			{
				if (strlen(cpName) < MAX_OPERANDS_LENGTH - 1)
				{
					bzero(mLineOperandsCString, strlen(mLineOperandsCString));
					strncpy(mLineOperandsCString, cpName, strlen(cpName) + 1);
				}

				free(cpName);
			}
		}
	}

	// Demangle comment if necessary.
	if (theCommentCString[0] && mDemangleCppNames)
	{
		char*	demString	=
			PrepareNameForDemangling(theCommentCString);

		if (demString)
		{
			char*	cpName	= cplus_demangle(demString, DEMANGLE_OPTS);

			free(demString);

			if (cpName)
			{
				if (strlen(cpName) < MAX_COMMENT_LENGTH - 1)
				{
					bzero(theCommentCString, strlen(theCommentCString));
					strncpy(theCommentCString, cpName, strlen(cpName) + 1);
				}

				free(cpName);
			}
		}
	}

	// Optionally add local offset.
	if (mShowLocalOffsets)
	{
		// Build a right-aligned string  with a '+' in it.
		snprintf((char*)&localOffsetString, mFieldWidths.offset,
			"%6lu", mLocalOffset);

		// Find the space that's followed by a nonspace.
		// *Reverse count to optimize for short functions.
		for (i = 0; i < 5; i++)
		{
			if (localOffsetString[i] == 0x20 &&
				localOffsetString[i + 1] != 0x20)
			{
				localOffsetString[i] = '+';
				break;
			}
		}

		if (theCodeCString)
			mLocalOffset += strlen(theCodeCString) / 2;

		// Fill up addrSpaces based on offset field width.
		i	= mFieldWidths.offset - 6;

		for (; i > 1; i--)
			addrSpaces[i - 2] = 0x20;
	}

	// Fill up instSpaces based on address field width.
	i	= mFieldWidths.address - 8;

	for (; i > 1; i--)
		instSpaces[i - 2] = 0x20;

	// Finally, assemble the new string.
	char	finalFormatCString[MAX_FORMAT_LENGTH]	= {0};
	UInt32	formatMarker	= 0;

	bzero(finalFormatCString, MAX_FORMAT_LENGTH);

	if (needNewLine)
		finalFormatCString[formatMarker++]	= '\n';

	if (mShowLocalOffsets)
		formatMarker += snprintf(&finalFormatCString[formatMarker],
			10, "%s", "%s %s");

	if (mLineOperandsCString[0])
	{
		if (theCommentCString[0])
			snprintf(&finalFormatCString[formatMarker],
				30, "%s", "%s %s%s %s%s %s%s %s%s\n");
		else
			snprintf(&finalFormatCString[formatMarker],
				30, "%s", "%s %s%s %s%s %s%s\n");
	}
	else
		snprintf(&finalFormatCString[formatMarker],
			30, "%s", "%s %s%s %s%s\n");

	char	theFinalCString[MAX_LINE_LENGTH];

	if (mShowLocalOffsets)
		snprintf(theFinalCString, MAX_LINE_LENGTH - 1,
			finalFormatCString, localOffsetString,
			addrSpaces, theAddressCString,
			instSpaces, theCodeCString,
			mnemSpaces, theMnemonicCString,
			opSpaces, mLineOperandsCString,
			commentSpaces, theCommentCString);
	else
		snprintf(theFinalCString, MAX_LINE_LENGTH - 1,
			finalFormatCString, theAddressCString,
			instSpaces, theCodeCString,
			mnemSpaces, theMnemonicCString,
			opSpaces, mLineOperandsCString,
			commentSpaces, theCommentCString);

	free((*ioLine)->chars);

	if (mSeparateLogicalBlocks && mEnteringNewBlock &&
		theFinalCString[0] != '\n')
	{
		(*ioLine)->length	= strlen(theFinalCString) + 1;
		(*ioLine)->chars	= malloc((*ioLine)->length + 1);
		(*ioLine)->chars[0]	= '\n';
		strncpy(&(*ioLine)->chars[1], theFinalCString, (*ioLine)->length);
	}
	else
	{
		(*ioLine)->length	= strlen(theFinalCString);
		(*ioLine)->chars	= malloc((*ioLine)->length + 1);
		strncpy((*ioLine)->chars, theFinalCString, (*ioLine)->length + 1);
	}

	// The test above can fail even if mEnteringNewBlock was true, so we
	// should reset it here.
	mEnteringNewBlock	= false;

	UpdateRegisters(*ioLine);
	PostProcessCodeLine(ioLine);
}

//	postProcessCodeLine:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)postProcessCodeLine: (Line**)ioLine
{}

//	printDataSections
// ----------------------------------------------------------------------------
//	Append data sections to output file.

- (BOOL)printDataSections
{
	FILE*	outFile;

	if (mOutputFilePath)
	{
		const char*	outPath		= CSTRING(mOutputFilePath);
		outFile					= fopen(outPath, "a");
	}
	else
		outFile	= stdout;

	if (!outFile)
	{
		perror("otx: unable to open output file");
		return false;
	}

	if (mDataSect.size)
	{
		if (fprintf(outFile, "\n(__DATA,__data) section\n") < 0)
		{
			perror("otx: unable to write to output file");
			return false;
		}

		[self printDataSection: &mDataSect toFile: outFile];
	}

	if (mCoalDataSect.size)
	{
		if (fprintf(outFile, "\n(__DATA,__coalesced_data) section\n") < 0)
		{
			perror("otx: unable to write to output file");
			return false;
		}

		[self printDataSection: &mCoalDataSect toFile: outFile];
	}

	if (mCoalDataNTSect.size)
	{
		if (fprintf(outFile, "\n(__DATA,__datacoal_nt) section\n") < 0)
		{
			perror("otx: unable to write to output file");
			return false;
		}

		[self printDataSection: &mCoalDataNTSect toFile: outFile];
	}

	if (mOutputFilePath)
	{
		if (fclose(outFile) != 0)
		{
			perror("otx: unable to close output file");
			return false;
		}
	}

	return true;
}

//	printDataSection:toFile:
// ----------------------------------------------------------------------------

- (void)printDataSection: (section_info*)inSect
				  toFile: (FILE*)outFile;
{
	UInt32	i, j, k, bytesLeft;
	UInt32	theDataSize			= inSect->size;
	char	theLineCString[70]	= {0};
	char*	theMachPtr			= (char*)mMachHeader;

	for (i = 0; i < theDataSize; i += 16)
	{
		bytesLeft	= theDataSize - i;

		if (bytesLeft < 16)	// last line
		{
			bzero(theLineCString, sizeof(theLineCString));
			snprintf(theLineCString,
				20 ,"%08x |", inSect->s.addr + i);

			unsigned char	theHexData[17]		= {0};
			unsigned char	theASCIIData[17]	= {0};

			memcpy(theHexData,
				(const void*)(theMachPtr + inSect->s.offset + i), bytesLeft);
			memcpy(theASCIIData,
				(const void*)(theMachPtr + inSect->s.offset + i), bytesLeft);

			j	= 10;

			for (k = 0; k < bytesLeft; k++)
			{
				if (!(k % 4))
					theLineCString[j++]	= 0x20;

				snprintf(&theLineCString[j], 4, "%02x", theHexData[k]);
				j += 2;

				if (theASCIIData[k] < 0x20 || theASCIIData[k] == 0x7f)
					theASCIIData[k]	= '.';
			}

			// Append spaces.
			for (; j < 48; j++)
				theLineCString[j]	= 0x20;

			// Append ASCII chars.
			snprintf(&theLineCString[j], 70, "%s\n", theASCIIData);
		}
		else	// first lines
		{			
			UInt32*			theHexPtr			= (UInt32*)
				(theMachPtr + inSect->s.offset + i);
			unsigned char	theASCIIData[17]	= {0};
			UInt8			j;

			memcpy(theASCIIData,
				(const void*)(theMachPtr + inSect->s.offset + i), 16);

			for (j = 0; j < 16; j++)
				if (theASCIIData[j] < 0x20 || theASCIIData[j] == 0x7f)
					theASCIIData[j]	= '.';

			if (OSHostByteOrder() == OSLittleEndian)
			{
				theHexPtr[0]	= OSSwapInt32(theHexPtr[0]);
				theHexPtr[1]	= OSSwapInt32(theHexPtr[1]);
				theHexPtr[2]	= OSSwapInt32(theHexPtr[2]);
				theHexPtr[3]	= OSSwapInt32(theHexPtr[3]);
			}

			snprintf(theLineCString, sizeof(theLineCString),
				"%08x | %08x %08x %08x %08x  %s\n",
				inSect->s.addr + i,
				theHexPtr[0], theHexPtr[1], theHexPtr[2], theHexPtr[3],
				theASCIIData);
		}

		if (fprintf(outFile, "%s", theLineCString) < 0)
		{
			perror("otx: unable to write to output file");
			return;
		}
	}
}

//	lineIsCode:
// ----------------------------------------------------------------------------
//	Line is code if first 8 chars are hex numbers and 9th is tab.

- (BOOL)lineIsCode: (const char*)inLine
{
	if (strlen(inLine) < 10)
		return false;

	UInt16	i;

	for (i = 0 ; i < 8; i++)
	{
		if ((inLine[i] < '0' || inLine[i] > '9') &&
			(inLine[i] < 'a' || inLine[i] > 'f'))
			return  false;
	}

	return (inLine[8] == '\t');
}

//	addressFromLine:
// ----------------------------------------------------------------------------

- (UInt32)addressFromLine: (const char*)inLine
{
	// sanity check
	if ((inLine[0] < '0' || inLine[0] > '9') &&
		(inLine[0] < 'a' || inLine[0] > 'f'))
		return 0;

	UInt32	theAddress	= 0;

	sscanf(inLine, "%08x", &theAddress);
	return theAddress;
}

//	lineIsFunction:
// ----------------------------------------------------------------------------
//	Subclasses may override

- (BOOL)lineIsFunction: (Line*)inLine
{
	return false;
}

//	codeFromLine:
// ----------------------------------------------------------------------------
//	Subclasses must override.

- (void)codeFromLine: (Line*)inLine
{}

//	checkThunk:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)checkThunk:(Line*)inLine
{}

//	commentForLine:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)commentForLine: (Line*)inLine
{}

//	commentForSystemCall
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)commentForSystemCall
{}

//	commentForMsgSend:fromLine:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)commentForMsgSend: (char*)ioComment
				 fromLine: (Line*)inLine
{}

//	chooseLine:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)chooseLine: (Line**)ioLine
{}

#pragma mark -
//	selectorForMsgSend:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (char*)selectorForMsgSend: (char*)ioComment
				   fromLine: (Line*)inLine
{
	return nil;
}

//	selectorIsFriendly:
// ----------------------------------------------------------------------------
//	A selector is friendly if it's associated method either:
//	- returns an id of the same class that sent the message
//	- doesn't alter the 'return' register (r3 or eax)

- (BOOL)selectorIsFriendly: (const char*)inSel
{
	if (!inSel)
		return false;

	UInt32			selLength	= strlen(inSel);
	UInt32			selCRC		= crc32(0, inSel, selLength);
	CheckedString	searchKey	= {selCRC, 0, nil};

	// Search for inSel in our list of friendly sels.
	CheckedString*	friendlySel	= bsearch(&searchKey,
		gFriendlySels, NUM_FRIENDLY_SELS, sizeof(CheckedString),
		(int (*)(const void*, const void*))CheckedString_Compare);

	if (friendlySel && friendlySel->length == selLength)
	{	// found a matching CRC, make sure it's not a collision.
		if (!strncmp(friendlySel->string, inSel, selLength))
			return true;
	}

	return false;
}

//	sendTypeFromMsgSend:
// ----------------------------------------------------------------------------

- (UInt8)sendTypeFromMsgSend: (char*)inString
{
	UInt8	sendType	= send;

	if (strlen(inString) != 13)	// not _objc_msgSend
	{
		if (strstr(inString, "Super_stret"))
			sendType	= sendSuper_stret;
		else if (strstr(inString, "Super"))
			sendType	= sendSuper;
		else if (strstr(inString, "_stret"))
			sendType	= send_stret;
		else if (strstr(inString, "_rtp"))
			sendType	= send_rtp;
		else	// Holy va_list!
		{
			sendType	= send_variadic;
			fprintf(stderr, "otx: [ExeProcessor sendTypeFromMsgSend]:"
				"variadic variant detected.\n");
		}
	}

	return sendType;
}

#pragma mark -
//	resetRegisters:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)resetRegisters: (Line*)inLine
{}

//	updateRegisters:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)updateRegisters: (Line*)inLine
{}

//	restoreRegisters:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (BOOL)restoreRegisters: (Line*)ioLine
{
	return false;
}

#pragma mark -
//	insertMD5
// ----------------------------------------------------------------------------

- (void)insertMD5
{
	char		md5Line[MAX_MD5_LINE];
	char		finalLine[MAX_MD5_LINE];
	NSString*	md5CommandString	= [NSString stringWithFormat:
		@"md5 -q '%@'", [mOFile path]];
	FILE*		md5Pipe				= popen(CSTRING(md5CommandString), "r");

	if (!md5Pipe)
	{
		fprintf(stderr, "otx: unable to open md5 pipe\n");
		return;
	}

	// In CLI mode, fgets(3) fails with EINTR "Interrupted system call". The
	// fix is to temporarily block the offending signal. Since we don't know
	// which signal is offensive, block them all.

	// Block all signals.
	sigset_t	oldSigs, newSigs;

	sigemptyset(&oldSigs);
	sigfillset(&newSigs);

	if (sigprocmask(SIG_BLOCK, &newSigs, &oldSigs) == -1)
	{
		perror("otx: unable to block signals");
		return;
	}

	if (!fgets(md5Line, MAX_MD5_LINE, md5Pipe))
	{
		perror("otx: unable to read from md5 pipe");
		return;
	}

	// Restore the signal mask to it's former glory.
	if (sigprocmask(SIG_SETMASK, &oldSigs, nil) == -1)
	{
		perror("otx: unable to restore signals");
		return;
	}

	if (pclose(md5Pipe) == -1)
	{
		fprintf(stderr, "otx: error closing md5 pipe\n");
		return;
	}

	strncpy(finalLine, "\nmd5: ", 7);
	strncat(finalLine, md5Line, strlen(md5Line));
	strncat(finalLine, "\n", 1);

	Line*	newLine	= malloc(sizeof(Line));

	bzero(newLine, sizeof(Line));

	newLine->length	= strlen(finalLine);
	newLine->chars	= malloc(newLine->length + 1);
	strncpy(newLine->chars, finalLine, newLine->length + 1);

	InsertLineAfter(newLine, mPlainLineListHead, &mPlainLineListHead);
}

//	prepareNameForDemangling:
// ----------------------------------------------------------------------------
//	For cplus_demangle(), we must remove any extra leading underscores and
//	any trailing colons. Caller owns the returned string.

- (char*)prepareNameForDemangling: (char*)inName
{
	char*	preparedName	= nil;

	// Bail if 1st char is not '_'.
	if (strchr(inName, '_') != inName)
		return nil;

	// Find start of mangled name or bail.
	char*	symString	= strstr(inName, "_Z");

	if (!symString)
		return nil;

	// Find trailing colon.
	UInt32	newSize		= strlen(symString);
	char*	colonPos	= strrchr(symString, ':');

	// Perform colonoscopy.
	if (colonPos)
		newSize	= colonPos - symString;

	// Copy adjusted symbol into new string.
	preparedName	= malloc(newSize + 1);

	bzero(preparedName, newSize + 1);
	strncpy(preparedName, symString, newSize);

	return preparedName;
}

#pragma mark -
//	objcClassPtrFromMethod:
// ----------------------------------------------------------------------------
//	Given a method imp address, return the class to which it belongs. This func
//	is called each time a new function is detected. If that function is known
//	to be an Obj-C method, it's class is returned. Otherwise this returns nil.

- (objc_class*)objcClassPtrFromMethod: (UInt32)inAddress;
{
	MethodInfo*	theInfo	= nil;

	FindClassMethodByAddress(&theInfo, inAddress);

	if (theInfo)
		return &theInfo->oc_class;

	return nil;
}

//	objcCatPtrFromMethod:
// ----------------------------------------------------------------------------
//	Same as above, for categories.

- (objc_category*)objcCatPtrFromMethod: (UInt32)inAddress;
{
	MethodInfo*	theInfo	= nil;

	FindCatMethodByAddress(&theInfo, inAddress);

	if (theInfo)
		return &theInfo->oc_cat;

	return nil;
}

//	objcMethodFromAddress:
// ----------------------------------------------------------------------------
//	Given a method imp address, return the MethodInfo for it.

- (MethodInfo*)objcMethodFromAddress: (UInt32)inAddress;
{
	MethodInfo*	theInfo	= nil;

	FindClassMethodByAddress(&theInfo, inAddress);

	if (theInfo)
		return theInfo;

	FindCatMethodByAddress(&theInfo, inAddress);

	return theInfo;
}

//	objcClass:fromName:
// ----------------------------------------------------------------------------
//	Given a class name, return the class itself. This func is used to tie
//	categories to classes. We have 2 pointers to the same name, so pointer
//	equality is sufficient.

- (BOOL)objcClass: (objc_class*)outClass
		 fromName: (const char*)inName;
{
	UInt32	i;

	for (i = 0; i < mNumClassMethodInfos; i++)
	{
		if (GetPointer((UInt32)mClassMethodInfos[i].oc_class.name,
			nil) == inName)
		{
			*outClass	= mClassMethodInfos[i].oc_class;
			return true;
		}
	}

	*outClass	= (objc_class){0};

	return false;
}

//	objcDescriptionFromObject:type:
// ----------------------------------------------------------------------------
//	Given an Obj-C object, return it's description.

- (char*)objcDescriptionFromObject: (const char*)inObject
							  type: (UInt8)inType
{
	char*	thePtr		= nil;
	UInt32	theValue	= 0;

	switch (inType)
	{
		case OCStrObjectType:
		{
			objc_string_object	ocString	= *(objc_string_object*)inObject;

			if (ocString.length == 0)
				break;

			theValue	= (UInt32)ocString.chars;

			break;
		}
		case OCClassType:
		{
			objc_class	ocClass	= *(objc_class*)inObject;

			theValue	= (ocClass.name != 0) ?
				(UInt32)ocClass.name : (UInt32)ocClass.isa;

			break;
		}
		case OCModType:
		{
			objc_module	ocMod	= *(objc_module*)inObject;

			theValue	= (UInt32)ocMod.name;

			break;
		}
		case OCGenericType:
			theValue	= *(UInt32*)inObject;

			break;

		default:
			break;
	}

	if (mSwapped)
		theValue	= OSSwapInt32(theValue);

	thePtr	= GetPointer(theValue, nil);

	return thePtr;
}

#pragma mark -
//	decodeMethodReturnType:output:
// ----------------------------------------------------------------------------

- (void)decodeMethodReturnType: (const char*)inTypeCode
						output: (char*)outCString
{
	UInt32	theNextChar	= 0;

	// Check for type specifiers.
	// r* <-> const char* ... VI <-> oneway unsigned int
	switch (inTypeCode[theNextChar++])
	{
		case 'r':
			strncpy(outCString, "const ", 7);
			break;
		case 'n':
			strncpy(outCString, "in ", 4);
			break;
		case 'N':
			strncpy(outCString, "inout ", 7);
			break;
		case 'o':
			strncpy(outCString, "out ", 5);
			break;
		case 'O':
			strncpy(outCString, "bycopy ", 8);
			break;
		case 'V':
			strncpy(outCString, "oneway ", 8);
			break;

		// No specifier found, roll back the marker.
		default:
			theNextChar--;
			break;
	}

	GetDescription(outCString, &inTypeCode[theNextChar]);
}

//	getDescription:forType:
// ----------------------------------------------------------------------------
//	"filer types" defined in objc/objc-class.h, NSCoder.h, and
// http://developer.apple.com/documentation/DeveloperTools/gcc-3.3/gcc/Type-encoding.html

- (void)getDescription: (char*)ioCString
			   forType: (const char*)inTypeCode
{
	if (!inTypeCode || !ioCString)
		return;

	char	theSuffixCString[50]	= {0};
	UInt32	theNextChar				= 0;
	UInt16	i						= 0;

/*
	char vs. BOOL

	data type		encoding
	ÑÑÑÑÑÑÑÑÑ		ÑÑÑÑÑÑÑÑ
	char			c
	BOOL			c
	char[100]		[100c]
	BOOL[100]		[100c]

	from <objc/objc.h>:
		typedef signed char		BOOL; 
		// BOOL is explicitly signed so @encode(BOOL) == "c" rather than "C" 
		// even if -funsigned-char is used.

	Ok, so BOOL is just a synonym for signed char, and the @encode directive
	can't be expected to desynonize that. Fair enough, but for our purposes,
	it would be nicer if BOOL was synonized to unsigned char instead. As they
	say- if wishes were recursive calls, beggars would have stack overflows.

	So, any occurence of 'c' may be a char or a BOOL. The best option I can
	see is to treat arrays as char arrays and atomic values as BOOL, and maybe
	let the user disagree via preferences. Since the data type of an array is
	decoded with a recursive call, we can use the following static variable
	for this purpose.

	As of otx 0.14b, letting the user override this behavior with a pref
	is left as an exercise for the reader.
*/
	static	BOOL	isArray	= false;

	// Convert '^^' prefix to '**' suffix.
	while (inTypeCode[theNextChar] == '^')
	{
		theSuffixCString[i++]	= '*';
		theNextChar++;
	}

	i	= 0;

	char	theTypeCString[MAX_TYPE_STRING_LENGTH]	= {0};

	// Now we can get at the basic type.
	switch (inTypeCode[theNextChar])
	{
		case '@':
		{
			if (inTypeCode[theNextChar + 1] == '"')
			{
				UInt32	classNameLength	=
					strlen(&inTypeCode[theNextChar + 2]);

				memcpy(theTypeCString, &inTypeCode[theNextChar + 2],
					classNameLength - 1);
			}
			else
				strncpy(theTypeCString, "id", 3);

			break;
		}

		case '#':
			strncpy(theTypeCString, "Class", 6);
			break;
		case ':':
			strncpy(theTypeCString, "SEL", 4);
			break;
		case '*':
			strncpy(theTypeCString, "char*", 6);
			break;
		case '?':
			strncpy(theTypeCString, "undefined", 10);
			break;
		case 'i':
			strncpy(theTypeCString, "int", 4);
			break;
		case 'I':
			strncpy(theTypeCString, "unsigned int", 13);
			break;
		// bitfield according to objc-class.h, C++ bool according to NSCoder.h.
		// The above URL expands on obj-class.h's definition of 'b' when used
		// in structs/unions, but NSCoder.h's definition seems to take
		// priority in return values.
		case 'B':
		case 'b':
			strncpy(theTypeCString, "bool", 5);
			break;
		case 'c':
			strncpy(theTypeCString, (isArray) ? "char" : "BOOL", 5);
			break;
		case 'C':
			strncpy(theTypeCString, "unsigned char", 14);
			break;
		case 'd':
			strncpy(theTypeCString, "double", 7);
			break;
		case 'f':
			strncpy(theTypeCString, "float", 6);
			break;
		case 'l':
			strncpy(theTypeCString, "long", 5);
			break;
		case 'L':
			strncpy(theTypeCString, "unsigned long", 14);
			break;
		case 'q':	// not in objc-class.h
			strncpy(theTypeCString, "long long", 10);
			break;
		case 'Q':	// not in objc-class.h
			strncpy(theTypeCString, "unsigned long long", 19);
			break;
		case 's':
			strncpy(theTypeCString, "short", 6);
			break;
		case 'S':
			strncpy(theTypeCString, "unsigned short", 15);
			break;
		case 'v':
			strncpy(theTypeCString, "void", 5);
			break;
		case '(':	// union- just copy the name
			while (inTypeCode[++theNextChar] != '=' &&
				   inTypeCode[theNextChar]   != ')'	&&
				   inTypeCode[theNextChar]   != '<'	&&
				   theNextChar < MAX_TYPE_STRING_LENGTH)
				theTypeCString[i++]	= inTypeCode[theNextChar];

			break;

		case '{':	// struct- just copy the name
			while (inTypeCode[++theNextChar] != '='	&&
				   inTypeCode[theNextChar]   != '}'	&&
				   inTypeCode[theNextChar]   != '<'	&&
				   theNextChar < MAX_TYPE_STRING_LENGTH)
				theTypeCString[i++]	= inTypeCode[theNextChar];

			break;

		case '[':	// arrayÉ	[12^f] <-> float*[12]
		{
			char	theArrayCCount[10]	= {0};

			while (inTypeCode[++theNextChar] >= '0' &&
				   inTypeCode[theNextChar]   <= '9')
				theArrayCCount[i++]	= inTypeCode[theNextChar];

			// Recursive madness. See 'char vs. BOOL' note above.
			char	theCType[MAX_TYPE_STRING_LENGTH]	= {0};

			isArray	= true;
			GetDescription(theCType, &inTypeCode[theNextChar]);
			isArray	= false;

			snprintf(theTypeCString, MAX_TYPE_STRING_LENGTH + 1, "%s[%s]",
				theCType, theArrayCCount);

			break;
		}

		default:
			strncpy(theTypeCString, "?", 2);
			fprintf(stderr, "otx: unknown encoded type: %c\n", inTypeCode[theNextChar]);

			break;
	}

	strncat(ioCString, theTypeCString, strlen(theTypeCString));

	if (theSuffixCString[0])
		strncat(ioCString, theSuffixCString, strlen(theSuffixCString));
}

#pragma mark -
//	entabLine:
// ----------------------------------------------------------------------------
//	A cheap and fast way to entab a line, assuming it contains no tabs already.
//	If tabs get added in the future, this WILL break. Single spaces are not
//	replaced with tabs, even when possible, since it would save no additional
//	bytes.

- (void)entabLine: (Line*)ioLine;
{
	if (!ioLine || !ioLine->chars)
		return;

	UInt32	i;			// oldLine marker
	UInt32	j	= 0;	// newLine marker

	char	entabbedLine[MAX_LINE_LENGTH]	= {0};
	UInt32	theOrigLength					= ioLine->length;

	// If 1st char is '\n', skip it.
	UInt32	firstChar	= (ioLine->chars[0] == '\n');

	if (firstChar)
		entabbedLine[j++]	= '\n';

	// Inspect 4 bytes at a time.
	for (i = firstChar; i < theOrigLength; i += 4)
	{
		// If fewer than 4 bytes remain, adding any tabs is pointless.
		if (i > theOrigLength - 4)
		{	// copy the remainder and split.
			while (i < theOrigLength)
				entabbedLine[j++] = ioLine->chars[i++];

			break;
		}

		// If the 4th char is not a space, the first 3 chars don't matter.
		if (ioLine->chars[i + 3] == 0x20)	// 4th char is a space...
		{
			if (ioLine->chars[i + 2] == 0x20)	// 3rd char is a space...
			{
				if (ioLine->chars[i + 1] == 0x20)	// 2nd char is a space...
				{
					if (ioLine->chars[i] == 0x20)	// all 4 chars are spaces!
						entabbedLine[j++] = '\t';	// write a tab and split
					else	// only the 1st char is not a space
					{		// write 1st char and tab
						entabbedLine[j++] = ioLine->chars[i];
						entabbedLine[j++] = '\t';
					}
				}
				else	// 2nd char is not a space
				{		// write 1st 2 chars and tab
					entabbedLine[j++] = ioLine->chars[i];
					entabbedLine[j++] = ioLine->chars[i + 1];
					entabbedLine[j++] = '\t';
				}
			}
			else	// 3rd char is not a space
			{		// copy all 4 chars
				memcpy(&entabbedLine[j], &ioLine->chars[i], 4);
				j += 4;
			}
		}
		else	// 4th char is not a space
		{		// copy all 4 chars
			memcpy(&entabbedLine[j], &ioLine->chars[i], 4);
			j += 4;
		}
	}

	// Replace the old C string with the new one.
	free(ioLine->chars);
	ioLine->length	= strlen(entabbedLine);
	ioLine->chars	= malloc(ioLine->length + 1);
	strncpy(ioLine->chars, entabbedLine, ioLine->length + 1);
}

#pragma mark -
#pragma mark Binary searches

//	findSymbolByAddress:
// ----------------------------------------------------------------------------

- (BOOL)findSymbolByAddress: (UInt32)inAddress
{
	if (!mFuncSyms)
		return false;

	nlist*	searchKey	= malloc(sizeof(nlist));

	searchKey->n_value	= inAddress;

	BOOL	symbolExists	= (bsearch(&searchKey,
		mFuncSyms, mNumFuncSyms, sizeof(nlist*),
		(int (*)(const void*, const void*))Sym_Compare) != nil);

	free(searchKey);

	return symbolExists;
}

//	findClassMethod:byAddress:
// ----------------------------------------------------------------------------

- (BOOL)findClassMethod: (MethodInfo**)outMI
			  byAddress: (UInt32)inAddress;
{
	if (!outMI)
		return false;

	if (!mClassMethodInfos)
	{
		*outMI	= nil;
		return false;
	}

	MethodInfo	searchKey	= {{nil, nil, (IMP)inAddress}, {0}, {0}, false};

	*outMI	= bsearch(&searchKey,
		mClassMethodInfos, mNumClassMethodInfos, sizeof(MethodInfo),
		(int (*)(const void*, const void*))MethodInfo_Compare);

	return (*outMI != nil);
}

//	findCatMethod:byAddress:
// ----------------------------------------------------------------------------

- (BOOL)findCatMethod: (MethodInfo**)outMI
			byAddress: (UInt32)inAddress;
{
	if (!outMI)
		return false;

	if (!mCatMethodInfos)
	{
		*outMI	= nil;
		return false;
	}

	MethodInfo	searchKey	= {{nil, nil, (IMP)inAddress}, {0}, {0}, false};

	*outMI	= bsearch(&searchKey,
		mCatMethodInfos, mNumCatMethodInfos, sizeof(MethodInfo),
		(int (*)(const void*, const void*))MethodInfo_Compare);

	return (*outMI != nil);
}

//	findIvar:inClass:withOffset:
// ----------------------------------------------------------------------------

- (BOOL)findIvar: (objc_ivar*)outIvar
		 inClass: (objc_class*)inClass
	  withOffset: (UInt32)inOffset
{
	if (!inClass || !outIvar)
		return false;

	// Loop thru inClass and all superclasses.
	objc_class*	theClassPtr		= inClass;
	objc_class	theDummyClass	= {0};
	char*		theSuperName	= nil;

	while (theClassPtr)
	{
		objc_ivar_list*	theIvars	= (objc_ivar_list*)
			GetPointer((UInt32)theClassPtr->ivars, nil);

		if (!theIvars)
		{	// Try again with the superclass.
			theSuperName	= GetPointer(
				(UInt32)theClassPtr->super_class, nil);

			if (!theSuperName)
				break;

			if (!ObjcClassFromName(&theDummyClass, theSuperName))
				break;

			theClassPtr	= &theDummyClass;

			continue;
		}

		UInt32	numIvars	= theIvars->ivar_count;

		if (mSwapped)
			numIvars	= OSSwapInt32(numIvars);

		// It would be nice to use bsearch(3) here, but there's too much
		// swapping.
		SInt64	begin	= 0;
		SInt64	end		= numIvars - 1;
		SInt64	split	= numIvars / 2;
		UInt32	offset;

		while (end >= begin)
		{
			offset	= theIvars->ivar_list[split].ivar_offset;

			if (mSwapped)
				offset	= OSSwapInt32(offset);

			if (offset == inOffset)
			{
				*outIvar	= theIvars->ivar_list[split];

				if (mSwapped)
					swap_objc_ivar(outIvar);

				return true;
			}

			if (offset > inOffset)
				end		= split - 1;
			else
				begin	= split + 1;

			split	= (begin + end) / 2;
		}

		// Try again with the superclass.
		theSuperName	= GetPointer((UInt32)theClassPtr->super_class, nil);

		if (!theSuperName)
			break;

		if (!ObjcClassFromName(&theDummyClass, theSuperName))
			break;

		theClassPtr	= &theDummyClass;
	}

	return false;
}

#pragma mark -
#pragma mark Stolen
// The getXXX methods were originally defined in
// cctools-590/otool/print_objc.c. These adaptations make use of member
// variables.

//	getObjcSymtab:andDefs:fromModule: (was get_symtab)
// ----------------------------------------------------------------------------
//	Removed the truncation flag. 'left' is no longer used by the caller.

- (BOOL)getObjcSymtab: (objc_symtab*)outSymTab
			  andDefs: (void***)outDefs
		   fromModule: (objc_module*)inModule;
{
	unsigned long	addr	= (unsigned long)inModule->symtab;
	unsigned long	i, left;

	bzero(outSymTab, sizeof(objc_symtab));

	for (i = 0; i < mNumObjcSects; i++)
	{
		if (addr >= mObjcSects[i].s.addr &&
			addr < mObjcSects[i].s.addr + mObjcSects[i].size)
		{
			left = mObjcSects[i].size -
				(addr - mObjcSects[i].s.addr);

			if (left >= sizeof(objc_symtab) - sizeof(void*))
			{
				memcpy(outSymTab, mObjcSects[i].contents +
					(addr - mObjcSects[i].s.addr),
					sizeof(objc_symtab) - sizeof(void*));
				left		-= sizeof(objc_symtab) - sizeof(void*);
				*outDefs	= (void**)(mObjcSects[i].contents +
					(addr - mObjcSects[i].s.addr) +
					sizeof(objc_symtab) - sizeof(void*));
			}
			else
			{
				memcpy(outSymTab, mObjcSects[i].contents +
					(addr - mObjcSects[i].s.addr), left);
				*outDefs	= nil;
			}

			if (mSwapped)
				swap_objc_symtab(outSymTab);

			return true;
		}
	}

	return false;
}

//	getObjcClass:fromDef: (was get_objc_class)
// ----------------------------------------------------------------------------

- (BOOL)getObjcClass: (objc_class*)outClass
			 fromDef: (UInt32)inDef;
{
	UInt32	i;

	for (i = 0; i < mNumObjcSects; i++)
	{
		if (inDef >= mObjcSects[i].s.addr &&
			inDef < mObjcSects[i].s.addr + mObjcSects[i].size)
		{
			*outClass	= *(objc_class*)(mObjcSects[i].contents +
				(inDef - mObjcSects[i].s.addr));

			if (mSwapped)
				swap_objc_class(outClass);

			return true;
		}
	}

	return false;
}

//	getObjcCategory:fromDef: (was get_objc_category)
// ----------------------------------------------------------------------------

- (BOOL)getObjcCategory: (objc_category*)outCat
				fromDef: (UInt32)inDef;
{
	UInt32	i;

	for (i = 0; i < mNumObjcSects; i++)
	{
		if (inDef >= mObjcSects[i].s.addr &&
			inDef < mObjcSects[i].s.addr + mObjcSects[i].size)
		{
			*outCat	= *(objc_category*)(mObjcSects[i].contents +
				(inDef - mObjcSects[i].s.addr));

			if (mSwapped)
				swap_objc_category(outCat);

			return true;
		}
	}

	return false;
}

//	getObjcMetaClass:fromClass:
// ----------------------------------------------------------------------------

- (BOOL)getObjcMetaClass: (objc_class*)outClass
			   fromClass: (objc_class*)inClass;
{
	if ((UInt32)inClass->isa >= mMetaClassSect.s.addr &&
		(UInt32)inClass->isa < mMetaClassSect.s.addr + mMetaClassSect.size)
	{
		*outClass	= *(objc_class*)(mMetaClassSect.contents +
			((UInt32)inClass->isa - mMetaClassSect.s.addr));

		if (mSwapped)
			swap_objc_class(outClass);

		return true;
	}

	return false;
}

//	getObjcMethodList:andMethods:fromAddress: (was get_method_list)
// ----------------------------------------------------------------------------
//	Removed the truncation flag. 'left' is no longer used by the caller.

- (BOOL)getObjcMethodList: (objc_method_list*)outList
			   andMethods: (objc_method**)outMethods
			  fromAddress: (UInt32)inAddress;
{
	UInt32	left, i;

	bzero(outList, sizeof(objc_method_list));

	for (i = 0; i < mNumObjcSects; i++)
	{
		if (inAddress >= mObjcSects[i].s.addr &&
			inAddress < mObjcSects[i].s.addr + mObjcSects[i].size)
		{
			left = mObjcSects[i].size -
				(inAddress - mObjcSects[i].s.addr);

			if (left >= sizeof(objc_method_list) -
				sizeof(objc_method))
			{
				memcpy(outList, mObjcSects[i].contents +
					(inAddress - mObjcSects[i].s.addr),
					sizeof(objc_method_list) - sizeof(objc_method));
				left -= sizeof(objc_method_list) -
					sizeof(objc_method);
				*outMethods = (objc_method*)(mObjcSects[i].contents +
					(inAddress - mObjcSects[i].s.addr) +
					sizeof(objc_method_list) - sizeof(objc_method));
			}
			else
			{
				memcpy(outList, mObjcSects[i].contents +
					(inAddress - mObjcSects[i].s.addr), left);
				left = 0;
				*outMethods = nil;
			}

			if (mSwapped)
				swap_objc_method_list(outList);

			return true;
		}
	}

	return false;
}

//	getPointer:outType:	(was get_pointer)
// ----------------------------------------------------------------------------
//	Convert a relative ptr to an absolute ptr. Return which data type is being
//	referenced in outType.

- (char*)getPointer: (UInt32)inAddr
			andType: (UInt8*)outType
{
	if (inAddr == 0)
		return nil;

	if (outType)
		*outType	= PointerType;

	char*	thePtr	= nil;
	UInt32	i;

			// (__TEXT,__cstring) (char*)
	if (inAddr >= mCStringSect.s.addr &&
		inAddr < mCStringSect.s.addr + mCStringSect.size)
	{
		thePtr = (mCStringSect.contents + (inAddr - mCStringSect.s.addr));

		// Make sure we're pointing to the beginning of a string,
		// not somewhere in the middle.
		if (*(thePtr - 1) != 0 && inAddr != mCStringSect.s.addr)
			thePtr	= nil;
	}
	else	// (__TEXT,__const) (Str255* sometimes)
	if (inAddr >= mConstTextSect.s.addr &&
		inAddr < mConstTextSect.s.addr + mConstTextSect.size)
	{
		thePtr	= (mConstTextSect.contents + (inAddr - mConstTextSect.s.addr));

		if (strlen(thePtr) == thePtr[0] + 1 && outType)
			*outType	= PStringType;
		else
			thePtr	= nil;
	}
	else	// (__TEXT,__literal4) (float)
	if (inAddr >= mLit4Sect.s.addr &&
		inAddr < mLit4Sect.s.addr + mLit4Sect.size)
	{
		thePtr	= (char*)((UInt32)mLit4Sect.contents +
			(inAddr - mLit4Sect.s.addr));

		if (outType)
			*outType	= FloatType;
	}
	else	// (__TEXT,__literal8) (double)
	if (inAddr >= mLit8Sect.s.addr &&
		inAddr < mLit8Sect.s.addr + mLit8Sect.size)
	{
		thePtr	= (char*)((UInt32)mLit8Sect.contents +
			(inAddr - mLit8Sect.s.addr));

		if (outType)
			*outType	= DoubleType;
	}

	if (thePtr)
		return thePtr;

			// (__OBJC,__cstring_object) (objc_string_object)
	if (inAddr >= mNSStringSect.s.addr &&
		inAddr < mNSStringSect.s.addr + mNSStringSect.size)
	{
		thePtr	= (char*)((UInt32)mNSStringSect.contents +
			(inAddr - mNSStringSect.s.addr));

		if (outType)
			*outType	= OCStrObjectType;
	}
	else	// (__OBJC,__class) (objc_class)
	if (inAddr >= mClassSect.s.addr &&
		inAddr < mClassSect.s.addr + mClassSect.size)
	{
		thePtr	= (char*)((UInt32)mClassSect.contents +
			(inAddr - mClassSect.s.addr));

		if (outType)
			*outType	= OCClassType;
	}
	else	// (__OBJC,__meta_class) (objc_class)
	if (inAddr >= mMetaClassSect.s.addr &&
		inAddr < mMetaClassSect.s.addr + mMetaClassSect.size)
	{
		thePtr	= (char*)((UInt32)mMetaClassSect.contents +
			(inAddr - mMetaClassSect.s.addr));

		if (outType)
			*outType	= OCClassType;
	}
	else	// (__OBJC,__module_info) (objc_module)
	if (inAddr >= mObjcModSect.s.addr &&
		inAddr < mObjcModSect.s.addr + mObjcModSect.size)
	{
		thePtr	= (char*)((UInt32)mObjcModSect.contents +
			(inAddr - mObjcModSect.s.addr));

		if (outType)
			*outType	= OCModType;
	}

			//  (__OBJC, ??) (char*)
			// __message_refs, __class_refs, __instance_vars, __symbols
	for (i = 0; !thePtr && i < mNumObjcSects; i++)
	{
		if (inAddr >= mObjcSects[i].s.addr &&
			inAddr < mObjcSects[i].s.addr + mObjcSects[i].size)
		{
			thePtr	= (char*)(mObjcSects[i].contents +
				(inAddr - mObjcSects[i].s.addr));

			if (outType)
				*outType	= OCGenericType;
		}
	}

	if (thePtr)
		return thePtr;

			// (__IMPORT,__pointers) (cf_string_object*)
	if (inAddr >= mImpPtrSect.s.addr &&
		inAddr < mImpPtrSect.s.addr + mImpPtrSect.size)
	{
		thePtr	= (char*)((UInt32)mImpPtrSect.contents +
			(inAddr - mImpPtrSect.s.addr));

		if (outType)
			*outType	= ImpPtrType;
	}

	if (thePtr)
		return thePtr;

			// (__DATA,__data) (char**)
	if (inAddr >= mDataSect.s.addr &&
		inAddr < mDataSect.s.addr + mDataSect.size)
	{
		thePtr	= (char*)(mDataSect.contents + (inAddr - mDataSect.s.addr));

		UInt8	theType		= DataGenericType;
		UInt32	theValue	= *(UInt32*)thePtr;

		if (mSwapped)
			theValue	= OSSwapInt32(theValue);

		if (theValue != 0)
		{
			theType	= PointerType;

			static	UInt32	recurseCount	= 0;

			while (theType == PointerType)
			{
				recurseCount++;

				if (recurseCount > 5)
				{
					theType	= DataGenericType;
					break;
				}

				thePtr	= GetPointer(theValue, &theType);

				if (!thePtr)
				{
					theType	= DataGenericType;
					break;
				}

				theValue	= *(UInt32*)thePtr;
			}

			recurseCount	= 0;
		}

		if (outType)
			*outType	= theType;
	}
	else	// (__DATA,__const) (void*)
	if (inAddr >= mConstDataSect.s.addr &&
		inAddr < mConstDataSect.s.addr + mConstDataSect.size)
	{
		thePtr	= (char*)((UInt32)mConstDataSect.contents +
			(inAddr - mConstDataSect.s.addr));

		if (outType)
		{
			UInt32	theID	= *(UInt32*)thePtr;

			if (mSwapped)
				theID	= OSSwapInt32(theID);

			if (theID == typeid_NSString)
				*outType	= OCStrObjectType;
			else
			{
				theID	= *(UInt32*)(thePtr + 4);

				if (mSwapped)
					theID	= OSSwapInt32(theID);

				if (theID == typeid_NSString)
					*outType	= CFStringType;
				else
					*outType	= DataConstType;
			}
		}
	}
	else	// (__DATA,__cfstring) (cf_string_object*)
	if (inAddr >= mCFStringSect.s.addr &&
		inAddr < mCFStringSect.s.addr + mCFStringSect.size)
	{
		thePtr	= (char*)((UInt32)mCFStringSect.contents +
			(inAddr - mCFStringSect.s.addr));

		if (outType)
			*outType	= CFStringType;
	}
	else	// (__DATA,__nl_symbol_ptr) (cf_string_object*)
	if (inAddr >= mNLSymSect.s.addr &&
		inAddr < mNLSymSect.s.addr + mNLSymSect.size)
	{
		thePtr	= (char*)((UInt32)mNLSymSect.contents +
			(inAddr - mNLSymSect.s.addr));

		if (outType)
			*outType	= NLSymType;
	}
	else	// (__DATA,__dyld) (function ptr)
	if (inAddr >= mDyldSect.s.addr &&
		inAddr < mDyldSect.s.addr + mDyldSect.size)
	{
		thePtr	= (char*)((UInt32)mDyldSect.contents +
			(inAddr - mDyldSect.s.addr));

		if (outType)
			*outType	= DYLDType;
	}

	// should implement these if they ever contain CFStrings or NSStrings
/*	else	// (__DATA, __coalesced_data) (?)
	if (localAddy >= mCoalDataSect.s.addr &&
		localAddy < mCoalDataSect.s.addr + mCoalDataSect.size)
	{
	}
	else	// (__DATA, __datacoal_nt) (?)
	if (localAddy >= mCoalDataNTSect.s.addr &&
		localAddy < mCoalDataNTSect.s.addr + mCoalDataNTSect.size)
	{
	}*/

	return thePtr;
}

#pragma mark -
//	speedyDelivery
// ----------------------------------------------------------------------------

- (void)speedyDelivery
{
	GetDescription				= GetDescriptionFuncType
		[self methodForSelector: GetDescriptionSel];
	LineIsCode					= LineIsCodeFuncType
		[self methodForSelector: LineIsCodeSel];
	LineIsFunction				= LineIsFunctionFuncType
		[self methodForSelector: LineIsFunctionSel];
	AddressFromLine				= AddressFromLineFuncType
		[self methodForSelector: AddressFromLineSel];
	CodeFromLine				= CodeFromLineFuncType
		[self methodForSelector: CodeFromLineSel];
	CheckThunk					= CheckThunkFuncType
		[self methodForSelector: CheckThunkSel];
	ProcessLine					= ProcessLineFuncType
		[self methodForSelector: ProcessLineSel];
	ProcessCodeLine				= ProcessCodeLineFuncType
		[self methodForSelector: ProcessCodeLineSel];
	PostProcessCodeLine			= PostProcessCodeLineFuncType
		[self methodForSelector: PostProcessCodeLineSel];
	ChooseLine					= ChooseLineFuncType
		[self methodForSelector: ChooseLineSel];
	EntabLine					= EntabLineFuncType
		[self methodForSelector: EntabLineSel];
	GetPointer					= GetPointerFuncType
		[self methodForSelector: GetPointerSel];
	CommentForLine				= CommentForLineFuncType
		[self methodForSelector: CommentForLineSel];
	CommentForSystemCall		= CommentForSystemCallFuncType
		[self methodForSelector: CommentForSystemCallSel];
	CommentForMsgSendFromLine	= CommentForMsgSendFromLineFuncType
		[self methodForSelector: CommentForMsgSendFromLineSel];
	SelectorForMsgSend			= SelectorForMsgSendFuncType
		[self methodForSelector: SelectorForMsgSendSel];
	SelectorIsFriendly			= SelectorIsFriendlyFuncType
		[self methodForSelector: SelectorIsFriendlySel];
	ResetRegisters				= ResetRegistersFuncType
		[self methodForSelector: ResetRegistersSel];
	UpdateRegisters				= UpdateRegistersFuncType
		[self methodForSelector: UpdateRegistersSel];
	RestoreRegisters			= RestoreRegistersFuncType
		[self methodForSelector: RestoreRegistersSel];
	SendTypeFromMsgSend			= SendTypeFromMsgSendFuncType
		[self methodForSelector: SendTypeFromMsgSendSel];
	PrepareNameForDemangling	= PrepareNameForDemanglingFuncType
		[self methodForSelector: PrepareNameForDemanglingSel];
	ObjcClassPtrFromMethod		= ObjcClassPtrFromMethodFuncType
		[self methodForSelector: ObjcClassPtrFromMethodSel];
	ObjcCatPtrFromMethod		= ObjcCatPtrFromMethodFuncType
		[self methodForSelector: ObjcCatPtrFromMethodSel];
	ObjcMethodFromAddress		= ObjcMethodFromAddressFuncType
		[self methodForSelector: ObjcMethodFromAddressSel];
	ObjcClassFromName			= ObjcClassFromNameFuncType
		[self methodForSelector: ObjcClassFromNameSel];
	ObjcDescriptionFromObject	= ObjcDescriptionFromObjectFuncType
		[self methodForSelector: ObjcDescriptionFromObjectSel];
	InsertLineBefore			= InsertLineBeforeFuncType
		[self methodForSelector: InsertLineBeforeSel];
	InsertLineAfter				= InsertLineAfterFuncType
		[self methodForSelector: InsertLineAfterSel];
	ReplaceLine					= ReplaceLineFuncType
		[self methodForSelector: ReplaceLineSel];
	FindIvar					= FindIvarFuncType
		[self methodForSelector: FindIvarSel];
	FindSymbolByAddress			= FindSymbolByAddressFuncType
		[self methodForSelector: FindSymbolByAddressSel];
	FindClassMethodByAddress	= FindClassMethodByAddressFuncType
		[self methodForSelector: FindClassMethodByAddressSel];
	FindCatMethodByAddress		= FindCatMethodByAddressFuncType
		[self methodForSelector: FindCatMethodByAddressSel];
}

//	printSymbol:
// ----------------------------------------------------------------------------
//	Used for symbol debugging.

- (void)printSymbol: (nlist)inSym
{
	fprintf(stderr, "----------------\n\n");
	fprintf(stderr, " n_strx = 0x%08x\n", inSym.n_un.n_strx);
	fprintf(stderr, " n_type = 0x%02x\n", inSym.n_type);
	fprintf(stderr, " n_sect = 0x%02x\n", inSym.n_sect);
	fprintf(stderr, " n_desc = 0x%04x\n", inSym.n_desc);
	fprintf(stderr, "n_value = 0x%08x (%u)\n\n", inSym.n_value, inSym.n_value);

	if ((inSym.n_type & N_STAB) != 0)
	{	// too complicated, see <mach-o/stab.h>
		fprintf(stderr, "STAB symbol\n");
	}
	else	// not a STAB
	{
		if ((inSym.n_type & N_PEXT) != 0)
			fprintf(stderr, "Private external symbol\n\n");
		else if ((inSym.n_type & N_EXT) != 0)
			fprintf(stderr, "External symbol\n\n");

		UInt8	theNType	= inSym.n_type & N_TYPE;
		UInt16	theRefType	= inSym.n_desc & REFERENCE_TYPE;

		fprintf(stderr, "Symbol type: ");

		if (theNType == N_ABS)
			fprintf(stderr, "Absolute\n");
		else if (theNType == N_SECT)
			fprintf(stderr, "Defined in section %u\n", inSym.n_sect);
		else if (theNType == N_INDR)
			fprintf(stderr, "Indirect\n");
		else
		{
			if (theNType == N_UNDF)
				fprintf(stderr, "Undefined\n");
			else if (theNType == N_PBUD)
				fprintf(stderr, "Prebound undefined\n");

			switch (theRefType)
			{
				case REFERENCE_FLAG_UNDEFINED_NON_LAZY:
					fprintf(stderr, "REFERENCE_FLAG_UNDEFINED_NON_LAZY\n");
					break;
				case REFERENCE_FLAG_UNDEFINED_LAZY:
					fprintf(stderr, "REFERENCE_FLAG_UNDEFINED_LAZY\n");
					break;
				case REFERENCE_FLAG_DEFINED:
					fprintf(stderr, "REFERENCE_FLAG_DEFINED\n");
					break;
				case REFERENCE_FLAG_PRIVATE_DEFINED:
					fprintf(stderr, "REFERENCE_FLAG_PRIVATE_DEFINED\n");
					break;
				case REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY:
					fprintf(stderr, "REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY\n");
					break;
				case REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY:
					fprintf(stderr, "REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY\n");
					break;

				default:
					break;
			}
		}
	}

	fprintf(stderr, "\n");
}

//	printBlocks:
// ----------------------------------------------------------------------------
//	Used for block debugging. Sublclasses may override.

- (void)printBlocks: (UInt32)inFuncIndex;
{}

@end
