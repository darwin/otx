/*
    Exe64Processor.m

    This file relies upon, and steals code from, the cctools source code
    available from: http://www.opensource.apple.com/darwinsource/

    This file is in the public domain.
*/

#import <Cocoa/Cocoa.h>

#import "Exe64Processor.h"
#import "Arch64Specifics.h"
#import "List64Utils.h"
#import "Objc64Accessors.h"
#import "Object64Loader.h"
#import "SysUtils.h"
#import "UserDefaultKeys.h"

@implementation Exe64Processor

// Exe64Processor is a base class that handles processor-independent issues.
// PPC64Processor and X8664Processor are subclasses that add functionality
// specific to those CPUs. The AppController class creates a new instance of
// one of those subclasses for each processing, and deletes the instance as
// soon as possible. Member variables may or may not be re-initialized before
// destruction. Do not reuse a single instance of those subclasses for
// multiple processings.

//  initWithURL:controller:options:
// ----------------------------------------------------------------------------

- (id)initWithURL: (NSURL*)inURL
       controller: (id)inController
          options: (ProcOptions*)inOptions;
{
    if (!inURL || !inController || !inOptions)
        return nil;

    if (self = [super initWithURL: inURL controller: inController
        options: inOptions])
    {
        iOFile                  = inURL;
        iController             = inController;
        iOpts                   = *inOptions;
        iCurrentFuncInfoIndex   = -1;

        // Load exe into RAM.
        NSError*    theError    = nil;
        NSData*     theData     = [NSData dataWithContentsOfURL: iOFile
            options: 0 error: &theError];

        if (!theData)
        {
            fprintf(stderr, "otx: error loading executable from disk: %s\n",
                UTF8STRING([theError localizedFailureReason]));
            [self release];
            return nil;
        }

        iRAMFileSize    = [theData length];

        if (iRAMFileSize < sizeof(iFileArchMagic))
        {
            fprintf(stderr, "otx: truncated executable file\n");
            [theData release];
            [self release];
            return nil;
        }

        iRAMFile    = malloc(iRAMFileSize);

        if (!iRAMFile)
        {
            fprintf(stderr, "otx: not enough memory to allocate mRAMFile\n");
            [theData release];
            [self release];
            return nil;
        }

        [theData getBytes: iRAMFile];

        iFileArchMagic  = *(UInt32*)iRAMFile;
        iExeIsFat   = (iFileArchMagic == FAT_MAGIC || iFileArchMagic == FAT_CIGAM);

        // Setup the C++ name demangler.
        if (iOpts.demangleCppNames)
        {
            iCPFiltPipe = popen("c++filt -_", "r+");

            if (!iCPFiltPipe)
                fprintf(stderr, "otx: unable to open c++filt pipe.\n");
        }

        [self speedyDelivery];
    }

    return self;
}

//  dealloc
// ----------------------------------------------------------------------------

- (void)dealloc
{
    if (iFuncSyms)
    {
        free(iFuncSyms);
        iFuncSyms   = NULL;
    }

    if (iClassMethodInfos)
    {
        free(iClassMethodInfos);
        iClassMethodInfos   = NULL;
    }

    if (iLineArray)
    {
        free(iLineArray);
        iLineArray = NULL;
    }

    [self deleteFuncInfos];
    [self deleteLinesFromList: iPlainLineListHead];
    [self deleteLinesFromList: iVerboseLineListHead];

    [super dealloc];
}

//  deleteFuncInfos
// ----------------------------------------------------------------------------

- (void)deleteFuncInfos
{
    if (!iFuncInfos)
        return;

    UInt32          i;
    UInt32          j;
    Function64Info* funcInfo;
    Block64Info*    blockInfo;

    for (i = 0; i < iNumFuncInfos; i++)
    {
        funcInfo    = &iFuncInfos[i];

        if (funcInfo->blocks)
        {
            for (j = 0; j < funcInfo->numBlocks; j++)
            {
                blockInfo   = &funcInfo->blocks[j];

                if (blockInfo->state.regInfos)
                {
                    free(blockInfo->state.regInfos);
                    blockInfo->state.regInfos   = NULL;
                }

                if (blockInfo->state.localSelves)
                {
                    free(blockInfo->state.localSelves);
                    blockInfo->state.localSelves    = NULL;
                }
            }

            free(funcInfo->blocks);
            funcInfo->blocks    = NULL;
        }
    }

    free(iFuncInfos);
    iFuncInfos  = NULL;
}

#pragma mark -
//  processExe:
// ----------------------------------------------------------------------------
//  The master processing method, designed to be executed in a separate thread.

- (BOOL)processExe: (NSString*)inOutputFilePath
{
    if (!iFileArchMagic)
    {
        fprintf(stderr, "otx: tried to process non-machO file\n");
        return NO;
    }

    iOutputFilePath = inOutputFilePath;
    iMachHeaderPtr  = NULL;

    if (![self loadMachHeader])
    {
        fprintf(stderr, "otx: failed to load mach header\n");
        return NO;
    }

    [self loadLCommands];

    NSMutableDictionary*    progDict    =
        [[NSMutableDictionary alloc] initWithObjectsAndKeys:
        [NSNumber numberWithBool: YES], PRNewLineKey,
        @"Calling otool", PRDescriptionKey,
        nil];

#ifdef OTX_CLI
    [iController reportProgress: progDict];
#else
    [iController performSelectorOnMainThread: @selector(reportProgress:)
        withObject: progDict waitUntilDone: NO];
#endif

    [progDict release];

    [self populateLineLists];

    if (gCancel == YES)
        return NO;

    progDict    = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
        [NSNumber numberWithBool: YES], PRNewLineKey,
        @"Gathering info", PRDescriptionKey,
        nil];

#ifdef OTX_CLI
    [iController reportProgress: progDict];
#else
    [iController performSelectorOnMainThread: @selector(reportProgress:)
        withObject: progDict waitUntilDone: NO];
#endif

    [progDict release];

    // Gather info about lines while they're virgin.
    [self gatherLineInfos];

    if (gCancel == YES)
        return NO;

    // Find functions and allocate funcInfo's.
    [self findFunctions];

    if (gCancel == YES)
        return NO;

    // Gather info about logical blocks. The second pass applies info
    // for backward branches.
    [self gatherFuncInfos];

    if (gCancel == YES)
        return NO;

    [self gatherFuncInfos];

    if (gCancel == YES)
        return NO;

    UInt32  progCounter = 0;
    double  progValue   = 0.0;

    progDict    = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
        [NSNumber numberWithBool: NO], PRIndeterminateKey,
        [NSNumber numberWithDouble: progValue], PRValueKey,
        [NSNumber numberWithBool: YES], PRNewLineKey,
        @"Generating file", PRDescriptionKey,
        nil];

#ifdef OTX_CLI
    [iController reportProgress: progDict];
#else
    [iController performSelectorOnMainThread: @selector(reportProgress:)
        withObject: progDict waitUntilDone: NO];
#endif

    [progDict release];

    Line64* theLine = iPlainLineListHead;

    // Loop thru lines.
    while (theLine)
    {
        if (!(progCounter % PROGRESS_FREQ))
        {
            if (gCancel == YES)
                return NO;

            progValue   = (double)progCounter / iNumLines * 100;
            progDict    = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                [NSNumber numberWithDouble: progValue], PRValueKey,
                nil];

#ifdef OTX_CLI
            [iController reportProgress: progDict];
#else
            [iController performSelectorOnMainThread: @selector(reportProgress:)
                withObject: progDict waitUntilDone: NO];
#endif

            [progDict release];
        }

        if (theLine->info.isCode)
        {
            ProcessCodeLine(&theLine);

            if (iOpts.entabOutput)
                EntabLine(theLine);
        }
        else
            ProcessLine(theLine);

        theLine = theLine->next;
        progCounter++;
    }

    if (gCancel == YES)
        return NO;

    progDict    = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
        [NSNumber numberWithBool: YES], PRIndeterminateKey,
        [NSNumber numberWithBool: YES], PRNewLineKey,
        @"Writing file", PRDescriptionKey,
        nil];

#ifdef OTX_CLI
    [iController reportProgress: progDict];
#else
    [iController performSelectorOnMainThread: @selector(reportProgress:)
        withObject: progDict waitUntilDone: NO];
#endif

    [progDict release];

    // Create output file.
    if (![self printLinesFromList: iPlainLineListHead])
    {
        return NO;
    }

    if (iOpts.dataSections)
    {
        if (![self printDataSections])
        {
            return NO;
        }
    }

    progDict = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
        [NSNumber numberWithBool: YES], PRCompleteKey,
        nil];

#ifdef OTX_CLI
    [iController reportProgress: progDict];
#else
    [iController performSelectorOnMainThread: @selector(reportProgress:)
        withObject: progDict waitUntilDone: NO];
#endif

    [progDict release];

    return YES;
}

//  populateLineLists
// ----------------------------------------------------------------------------

- (BOOL)populateLineLists
{
    Line64* thePrevVerboseLine  = NULL;
    Line64* thePrevPlainLine    = NULL;

    // Read __text lines.
    [self populateLineList: &iVerboseLineListHead verbosely: YES
        fromSection: "__text" afterLine: &thePrevVerboseLine
        includingPath: YES];

    [self populateLineList: &iPlainLineListHead verbosely: NO
        fromSection: "__text" afterLine: &thePrevPlainLine
        includingPath: YES];

    // Read __coalesced_text lines.
    if (iCoalTextSect.size)
    {
        [self populateLineList: &iVerboseLineListHead verbosely: YES
            fromSection: "__coalesced_text" afterLine: &thePrevVerboseLine
            includingPath: NO];

        [self populateLineList: &iPlainLineListHead verbosely: NO
            fromSection: "__coalesced_text" afterLine: &thePrevPlainLine
            includingPath: NO];
    }

    // Read __textcoal_nt lines.
    if (iCoalTextNTSect.size)
    {
        [self populateLineList: &iVerboseLineListHead verbosely: YES
            fromSection: "__textcoal_nt" afterLine: &thePrevVerboseLine
            includingPath: NO];

        [self populateLineList: &iPlainLineListHead verbosely: NO
            fromSection: "__textcoal_nt" afterLine: &thePrevPlainLine
            includingPath: NO];
    }

    // Connect the 2 lists.
    Line64* verboseLine = iVerboseLineListHead;
    Line64* plainLine   = iPlainLineListHead;

    while (verboseLine && plainLine)
    {
        verboseLine->alt    = plainLine;
        plainLine->alt      = verboseLine;

        verboseLine = verboseLine->next;
        plainLine   = plainLine->next;
    }

    // Optionally insert md5.
    if (iOpts.checksum)
        [self insertMD5];

    return YES;
}

//  populateLineList:verbosely:fromSection:afterLine:includingPath:
// ----------------------------------------------------------------------------

- (BOOL)populateLineList: (Line64**)inList
               verbosely: (BOOL)inVerbose
             fromSection: (char*)inSectionName
               afterLine: (Line64**)inLine
           includingPath: (BOOL)inIncludePath
{
    char cmdString[1000] = "";
    NSString* otoolPath = [self pathForTool: @"otool"];

    // otool freaks out when somebody says -arch and it's not a unibin.
    if (iExeIsFat)
        snprintf(cmdString, MAX_ARCH_STRING_LENGTH + [otoolPath length],
            "%s -arch %s", [otoolPath UTF8String], iArchString);
    else
        strncpy(cmdString, [otoolPath UTF8String], [otoolPath length]);

    NSString*   oPath       = [iOFile path];
    NSString*   otoolString = [NSString stringWithFormat:
        @"%s %s -s __TEXT %s \"%@\"%s", cmdString,
        (inVerbose) ? "-V" : "-v", inSectionName, oPath,
        (inIncludePath) ? "" : " | sed '1 d'"];
    FILE*       otoolPipe   = popen(UTF8STRING(otoolString), "r");

    if (!otoolPipe)
    {
        fprintf(stderr, "otx: unable to open %s otool pipe\n",
            (inVerbose) ? "verbose" : "plain");
        return NO;
    }

    char theCLine[MAX_LINE_LENGTH];

    while (fgets(theCLine, MAX_LINE_LENGTH, otoolPipe))
    {
        // Many thanx to Peter Hosey for the calloc speed test.
        // http://boredzo.org/blog/archives/2006-11-26/calloc-vs-malloc

        Line64* theNewLine  = calloc(1, sizeof(Line64));

        theNewLine->length  = strlen(theCLine);
        theNewLine->chars   = malloc(theNewLine->length + 1);
        strncpy(theNewLine->chars, theCLine,
            theNewLine->length + 1);

        // Add the line to the list.
        InsertLineAfter(theNewLine, *inLine, inList);

        *inLine = theNewLine;
    }

    if (pclose(otoolPipe) == -1)
    {
        perror((inVerbose) ? "otx: unable to close verbose otool pipe" :
            "otx: unable to close plain otool pipe");
        return NO;
    }

    return YES;
}

#pragma mark -
//  gatherLineInfos
// ----------------------------------------------------------------------------
//  To make life easier as we make changes to the lines, whatever info we need
//  is harvested early here.

- (void)gatherLineInfos
{
    Line64*         theLine     = iPlainLineListHead;
    UInt32          progCounter = 0;

    while (theLine)
    {
        if (!(progCounter % (PROGRESS_FREQ * 5)))
        {
            if (gCancel == YES)
                return;

//            [NSThread sleepForTimeInterval: 0.0];
        }

        if (LineIsCode(theLine->chars))
        {
            theLine->info.isCode = YES;
            theLine->info.address = AddressFromLine(theLine->chars);
            CodeFromLine(theLine);  // FIXME: return a value like the cool kids do.

            if (theLine->alt)
            {
                theLine->alt->info.isCode = theLine->info.isCode;
                theLine->alt->info.address = theLine->info.address;
                theLine->alt->info.codeLength = theLine->info.codeLength;
                memcpy(theLine->alt->info.code, theLine->info.code,
                    sizeof(theLine->info.code));
            }

            CheckThunk(theLine);
        }
        else    // not code...
        {
            if (strstr(theLine->chars, "(__TEXT,__coalesced_text)"))
                iEndOfText  = iCoalTextSect.s.addr + iCoalTextSect.s.size;
            else if (strstr(theLine->chars, "(__TEXT,__textcoal_nt)"))
                iEndOfText  = iCoalTextNTSect.s.addr + iCoalTextNTSect.s.size;
        }

        theLine = theLine->next;
        progCounter++;
        iNumLines++;
    }

    iEndOfText  = iTextSect.s.addr + iTextSect.s.size;
}

//  findFunctions
// ----------------------------------------------------------------------------

- (void)findFunctions
{
    // Loop once to flag all funcs.
    Line64* theLine = iPlainLineListHead;

    while (theLine)
    {
        theLine->info.isFunction    = LineIsFunction(theLine);

        if (theLine->alt)
            theLine->alt->info.isFunction   = theLine->info.isFunction;

        theLine = theLine->next;
    }

    // Loop again to allocate funcInfo's.
    theLine = iPlainLineListHead;
    iLineArray = calloc(iNumLines, sizeof(Line64*));
    iNumCodeLines = 0;

    while (theLine)
    {
        if (theLine->info.isFunction)
        {
            iNumFuncInfos++;
            iFuncInfos  = realloc(iFuncInfos,
                sizeof(Function64Info) * iNumFuncInfos);

            UInt32  genericFuncNum  = 0;

            if (theLine->prev && theLine->prev->info.isCode)
                genericFuncNum  = ++iCurrentGenericFuncNum;

            iFuncInfos[iNumFuncInfos - 1]   = (Function64Info)
                {theLine->info.address, NULL, 0, genericFuncNum};
        }

        if (theLine->info.isCode)
            iLineArray[iNumCodeLines++] = theLine;

        theLine = theLine->next;
    }
}

//  processLine:
// ----------------------------------------------------------------------------

- (void)processLine: (Line64*)ioLine;
{
    if (!strlen(ioLine->chars))
        return;

    // otool is inconsistent in printing section headers. Sometimes it
    // prints "Contents of (x)" and sometimes just "(x)". We'll take this
    // opportunity to use the shorter version in all cases.
    char*   theContentsString       = "Contents of ";
    UInt8   theContentsStringLength = strlen(theContentsString);
    char*   theTextSegString        = "(__TEXT,__";

    // Kill the "Contents of" if it exists.
    if (strstr(ioLine->chars, theContentsString))
    {
        char    theTempLine[MAX_LINE_LENGTH];

        theTempLine[0]  = '\n';
        theTempLine[1]  = 0;

        strncat(theTempLine, &ioLine->chars[theContentsStringLength],
            strlen(&ioLine->chars[theContentsStringLength]));

        ioLine->length  = strlen(theTempLine);
        strncpy(ioLine->chars, theTempLine, ioLine->length + 1);

        return;
    }
    else if (strstr(ioLine->chars, theTextSegString))
    {
        if (strstr(ioLine->chars, "__coalesced_text)"))
        {
            iEndOfText      = iCoalTextSect.s.addr + iCoalTextSect.s.size;
            iLocalOffset    = 0;
        }
        else if (strstr(ioLine->chars, "__textcoal_nt)"))
        {
            iEndOfText      = iCoalTextNTSect.s.addr + iCoalTextNTSect.s.size;
            iLocalOffset    = 0;
        }

        char    theTempLine[MAX_LINE_LENGTH];

        theTempLine[0]  = '\n';
        theTempLine[1]  = 0;

        strncat(theTempLine, ioLine->chars, strlen(ioLine->chars));

        ioLine->length++;
        ioLine->chars = (char*)realloc(ioLine->chars, ioLine->length + 1);
        strncpy(ioLine->chars, theTempLine, ioLine->length + 1);

        return;
    }

    // If we got here, we have a symbol name.
    if (iOpts.demangleCppNames)
    {
        if (strstr(ioLine->chars, "__Z") == ioLine->chars)
        {
            char    demangledName[MAX_COMMENT_LENGTH];

            // Replace trailing colon with \0.
            char*   colonPos    = strchr(ioLine->chars, ':');

            if (colonPos)
                *colonPos   = 0;

            fputs(ioLine->chars, iCPFiltPipe);
            fputs("\n", iCPFiltPipe);
            fgets(demangledName, MAX_COMMENT_LENGTH, iCPFiltPipe);

            free(ioLine->chars);
            ioLine->length  = strlen(demangledName);
            ioLine->chars   = malloc(ioLine->length + 1);

            strncpy(ioLine->chars, demangledName, ioLine->length + 1);
        }
    }
}

//  processCodeLine:
// ----------------------------------------------------------------------------

- (void)processCodeLine: (Line64**)ioLine;
{
    if (!ioLine || !(*ioLine) || !((*ioLine)->chars))
    {
        fprintf(stderr, "otx: tried to process NULL code line\n");
        return;
    }

    ChooseLine(ioLine);

    // Much thanx to Blake C. for the implicit memcpy info.
    // http://yamacdev.blogspot.com/2006/12/implicit-memcpy3-calls.html

    UInt32  theOrigLength           = (*ioLine)->length;
    char    localOffsetString[9]    = {0};
    char    theAddressCString[17]    = {0};
    char    theMnemonicCString[20]  = {0};

    char    addrSpaces[MAX_FIELD_SPACING];
    char    instSpaces[MAX_FIELD_SPACING];
    char    mnemSpaces[MAX_FIELD_SPACING];
    char    opSpaces[MAX_FIELD_SPACING];
    char    commentSpaces[MAX_FIELD_SPACING];
    char    theOrigCommentCString[MAX_COMMENT_LENGTH];
    char    theCommentCString[MAX_COMMENT_LENGTH];

    theOrigCommentCString[0]    = 0;
    theCommentCString[0]        = 0;

    // Swap in saved registers if necessary
    BOOL    needNewLine = RestoreRegisters(*ioLine);

    iLineOperandsCString[0] = 0;

    char*   origFormatString    = "%s\t%s\t%s%n";
    UInt32  consumedAfterOp     = 0;

    // The address and mnemonic always exist, separated by a tab.
    sscanf((*ioLine)->chars, origFormatString, theAddressCString,
        theMnemonicCString, iLineOperandsCString, &consumedAfterOp);

    // If we didn't grab everything up to the newline, there's a comment
    // remaining. Copy it, starting after the preceding tab.
    if (consumedAfterOp && consumedAfterOp < theOrigLength - 1)
    {
        if (iLineOperandsCString[0] == '*' &&
            (iLineOperandsCString[1] == '+' || iLineOperandsCString[1] == '-'))
        {   // ObjC method call with whitespace
            char    dummyAddressCString[17] = {0};
            char    dummyMnemonicCString[20] = {0};

            sscanf((*ioLine)->chars, "%s\t%s\t%[^\t\n]s", dummyAddressCString,
                dummyMnemonicCString, iLineOperandsCString);
        }
        else    // regular comment
        {
            UInt32  origCommentLength   = theOrigLength - consumedAfterOp - 1;

            strncpy(theOrigCommentCString, (*ioLine)->chars + consumedAfterOp + 1,
                origCommentLength);

            // Add the null terminator.
            theOrigCommentCString[origCommentLength - 1]    = 0;
        }
    }

    char theCodeCString[32] = {0};
    UInt8* inBuffer = (*ioLine)->info.code;
    char codeFormatString[MAX_FORMAT_LENGTH] = {0};
    SInt16 i;

    for (i = 0; i < (*ioLine)->info.codeLength; i++ )
        strncat(codeFormatString, "%02x", 4);

    snprintf(theCodeCString, 31, codeFormatString,
        inBuffer[0], inBuffer[1], inBuffer[2], inBuffer[3],
        inBuffer[4], inBuffer[5], inBuffer[6], inBuffer[7],
        inBuffer[8], inBuffer[9], inBuffer[10], inBuffer[11],
        inBuffer[12], inBuffer[13], inBuffer[14]);

    i = iFieldWidths.instruction - strlen(theCodeCString);

    mnemSpaces[i - 1] = 0;

    for (; i > 1; i--)
        mnemSpaces[i - 2] = 0x20;

    i = iFieldWidths.mnemonic - strlen(theMnemonicCString);

    opSpaces[i - 1] = 0;

    for (; i > 1; i--)
        opSpaces[i - 2] = 0x20;

    // Fill up commentSpaces based on operands field width.
    if (iLineOperandsCString[0] && theOrigCommentCString[0])
    {
        i   = iFieldWidths.operands - strlen(iLineOperandsCString);

        commentSpaces[i - 1]    = 0;

        for (; i > 1; i--)
            commentSpaces[i - 2]    = 0x20;
    }

    // Remove "; symbol stub for: "
    if (theOrigCommentCString[0])
    {
        char*   theSubstring    =
            strstr(theOrigCommentCString, "; symbol stub for: ");

        if (theSubstring)
            strncpy(theCommentCString, &theOrigCommentCString[19],
                strlen(&theOrigCommentCString[19]) + 1);
        else
            strncpy(theCommentCString, theOrigCommentCString,
                strlen(theOrigCommentCString) + 1);
    }

    BOOL    needFuncName = NO;
    char    theMethCName[1000];

    theMethCName[0] = 0;

    // Check if this is the beginning of a function.
    if ((*ioLine)->info.isFunction)
    {
        // Squash the new block flag, just in case.
        iEnteringNewBlock = NO;

        // New function, new local offset count and current func.
        iLocalOffset    = 0;
        iCurrentFuncPtr = (*ioLine)->info.address;

        // Try to build the method name.
        Method64Info* methodInfoPtr   = NULL;
        Method64Info  methodInfo;

        if (GetObjcMethodFromAddress(&methodInfoPtr, iCurrentFuncPtr))
        {
            methodInfo  = *methodInfoPtr;

            char*   className   = NULL;

            if (methodInfo.oc_class.data)
            {
                objc2_class_ro_t* roData = (objc2_class_ro_t*)(iDataSect.contents +
                    (uintptr_t)(methodInfo.oc_class.data - iDataSect.s.addr));

                UInt64 name = roData->name;

                if (iSwapped)
                    name = OSSwapInt64(name);

                className = GetPointer(name, NULL);
            }

//            char*   catName     = NULL;

            /*if (theSwappedInfo.oc_cat.category_name)
            {
                className   = GetPointer(
                    theSwappedInfo.oc_cat.class_name, NULL);
                catName     = GetPointer(
                    theSwappedInfo.oc_cat.category_name, NULL);
            }
            else if (theSwappedInfo.oc_class.data.name)
            {
                className   = GetPointer(
                    theSwappedInfo.oc_class.name, NULL);
            }*/

            if (className)
            {
                char*   selName = GetPointer(methodInfo.m.name, NULL);

                if (selName)
                {
                    if (!methodInfo.m.types)
                        return;

                    char*   methTypes   =
                        GetPointer(methodInfo.m.types, NULL);

                    if (methTypes)
                    {
                        char    returnCType[MAX_TYPE_STRING_LENGTH];

                        returnCType[0]  = 0;

                        [self decodeMethodReturnType: methTypes
                            output: returnCType];

/*                        if (catName)
                        {
                            char*   methNameFormat  = iOpts.returnTypes ?
                                "\n%1$c(%5$s)[%2$s(%3$s) %4$s]\n" :
                                "\n%c[%s(%s) %s]\n";

                            snprintf(theMethCName, 1000,
                                methNameFormat,
                                (theSwappedInfo.inst) ? '-' : '+',
                                className, catName, selName, returnCType);
                        }
                        else*/
                        //{
                            char*   methNameFormat  = iOpts.returnTypes ?
                                "\n%1$c(%4$s)[%2$s %3$s]\n" : "\n%c[%s %s]\n";

                            snprintf(theMethCName, 1000,
                                methNameFormat,
                                (methodInfo.inst) ? '-' : '+',
                                className, selName, returnCType);
                        //}
                    }
                }
            }
        }   // if (GetObjcMethodFromAddress(&theSwappedInfoPtr, mCurrentFuncPtr))

        // Add or replace the method name if possible, else add '\n'.
        if ((*ioLine)->prev && (*ioLine)->prev->info.isCode)    // prev line is code
        {
            if (theMethCName[0])
            {
                Line64* theNewLine  = malloc(sizeof(Line64));

                theNewLine->length  = strlen(theMethCName);
                theNewLine->chars   = malloc(theNewLine->length + 1);

                strncpy(theNewLine->chars, theMethCName,
                    theNewLine->length + 1);
                InsertLineBefore(theNewLine, *ioLine, &iPlainLineListHead);
            }
            else if ((*ioLine)->info.address == iAddrDyldStubBindingHelper)
            {
                Line64* theNewLine  = malloc(sizeof(Line64));
                char*   theDyldName = "\ndyld_stub_binding_helper:\n";

                theNewLine->length  = strlen(theDyldName);
                theNewLine->chars   = malloc(theNewLine->length + 1);

                strncpy(theNewLine->chars, theDyldName, theNewLine->length + 1);
                InsertLineBefore(theNewLine, *ioLine, &iPlainLineListHead);
            }
            else if ((*ioLine)->info.address == iAddrDyldFuncLookupPointer)
            {
                Line64* theNewLine  = malloc(sizeof(Line64));
                char*   theDyldName = "\n__dyld_func_lookup:\n";

                theNewLine->length  = strlen(theDyldName);
                theNewLine->chars   = malloc(theNewLine->length + 1);

                strncpy(theNewLine->chars, theDyldName, theNewLine->length + 1);
                InsertLineBefore(theNewLine, *ioLine, &iPlainLineListHead);
            }
            else
                needFuncName = YES;
        }
        else    // prev line is not code
        {
            if (theMethCName[0])
            {
                Line64* theNewLine  = malloc(sizeof(Line64));

                theNewLine->length  = strlen(theMethCName);
                theNewLine->chars   = malloc(theNewLine->length + 1);

                strncpy(theNewLine->chars, theMethCName,
                    theNewLine->length + 1);
                ReplaceLine((*ioLine)->prev, theNewLine, &iPlainLineListHead);
            }
            else
            {   // theMethName sux, add '\n' to otool's method name.
                char    theNewLine[MAX_LINE_LENGTH];

                if ((*ioLine)->prev->chars[0] != '\n')
                {
                    theNewLine[0]   = '\n';
                    theNewLine[1]   = 0;
                }
                else
                    theNewLine[0]   = 0;

                strncat(theNewLine, (*ioLine)->prev->chars,
                    (*ioLine)->prev->length);

                free((*ioLine)->prev->chars);
                (*ioLine)->prev->length = strlen(theNewLine);
                (*ioLine)->prev->chars  = malloc((*ioLine)->prev->length + 1);
                strncpy((*ioLine)->prev->chars, theNewLine,
                    (*ioLine)->prev->length + 1);
            }
        }

        ResetRegisters(*ioLine);
    }   // if ((*ioLine)->info.isFunction)

    // Find a comment if necessary.
    if (!theCommentCString[0])
    {
        CommentForLine(*ioLine);

        UInt32  origCommentLength   = strlen(iLineCommentCString);

        if (origCommentLength)
        {
            char    tempComment[MAX_COMMENT_LENGTH];
            UInt32  i, j = 0;

            // Escape newlines, carriage returns and tabs.
            for (i = 0; i < origCommentLength; i++)
            {
                if (iLineCommentCString[i] == '\n')
                {
                    tempComment[j++]    = '\\';
                    tempComment[j++]    = 'n';
                }
                else if (iLineCommentCString[i] == '\r')
                {
                    tempComment[j++]    = '\\';
                    tempComment[j++]    = 'r';
                }
                else if (iLineCommentCString[i] == '\t')
                {
                    tempComment[j++]    = '\\';
                    tempComment[j++]    = 't';
                }
                else
                    tempComment[j++]    = iLineCommentCString[i];
            }

            // Add the null terminator.
            tempComment[j]  = 0;

            if (iLineOperandsCString[0])
                strncpy(theCommentCString, tempComment,
                    strlen(tempComment) + 1);
            else
                strncpy(iLineOperandsCString, tempComment,
                    strlen(tempComment) + 1);

            // Fill up commentSpaces based on operands field width.
            SInt32  k   = iFieldWidths.operands - strlen(iLineOperandsCString);

            commentSpaces[k - 1]    = 0;

            for (; k > 1; k--)
                commentSpaces[k - 2]    = 0x20;
        }
    }   // if (!theCommentCString[0])
    else    // otool gave us a comment.
    {
        // Optionally modify otool's comment.
        if (iOpts.verboseMsgSends)
            CommentForMsgSendFromLine(theCommentCString, *ioLine);
    }

    // Demangle operands if necessary.
    if (iLineOperandsCString[0] && iOpts.demangleCppNames)
    {
        if (strstr(iLineOperandsCString, "__Z") == iLineOperandsCString)
        {
            char    demangledName[MAX_COMMENT_LENGTH];

            fputs(iLineOperandsCString, iCPFiltPipe);
            fputs("\n", iCPFiltPipe);
            fgets(demangledName, MAX_COMMENT_LENGTH, iCPFiltPipe);

            // Replace trailing newline with \0.
            char*   colonPos    = strchr(demangledName, '\n');

            if (colonPos)
                *colonPos   = 0;

            UInt32  demangledLength = strlen(demangledName);

            if (demangledLength < MAX_OPERANDS_LENGTH - 1)
                strncpy(iLineOperandsCString, demangledName, demangledLength + 1);
        }
    }

    // Demangle comment if necessary.
    if (theCommentCString[0] && iOpts.demangleCppNames)
    {
        if (strstr(theCommentCString, "__Z") == theCommentCString)
        {
            char    demangledName[MAX_COMMENT_LENGTH];

            fputs(theCommentCString, iCPFiltPipe);
            fputs("\n", iCPFiltPipe);
            fgets(demangledName, MAX_COMMENT_LENGTH, iCPFiltPipe);

            // Replace trailing newline with \0.
            char*   colonPos    = strchr(demangledName, '\n');

            if (colonPos)
                *colonPos   = 0;

            UInt32  demangledLength = strlen(demangledName);

            if (demangledLength < MAX_OPERANDS_LENGTH - 1)
                strncpy(theCommentCString, demangledName, demangledLength + 1);
        }
    }

    // Optionally add local offset.
    if (iOpts.localOffsets)
    {
        // Build a right-aligned string  with a '+' in it.
        snprintf((char*)&localOffsetString, iFieldWidths.offset,
            "%6lu", iLocalOffset);

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
            iLocalOffset += strlen(theCodeCString) / 2;

        // Fill up addrSpaces based on offset field width.
        i   = iFieldWidths.offset - 6;

        addrSpaces[i - 1] = 0;

        for (; i > 1; i--)
            addrSpaces[i - 2] = 0x20;
    }

    // Fill up instSpaces based on address field width.
    i   = iFieldWidths.address - 16;

    instSpaces[i - 1] = 0;

    for (; i > 1; i--)
        instSpaces[i - 2] = 0x20;

    // Insert a generic function name if needed.
    if (needFuncName)
    {
        Function64Info  searchKey   = {(*ioLine)->info.address, NULL, 0, 0};
        Function64Info* funcInfo    = bsearch(&searchKey,
            iFuncInfos, iNumFuncInfos, sizeof(Function64Info),
            (COMPARISON_FUNC_TYPE)Function64_Info_Compare);

        // sizeof(UINT32_MAX) + '\n' * 2 + ':' + null term
        UInt8   maxlength   = ANON_FUNC_BASE_LENGTH + 14;
        Line64* funcName    = calloc(1, sizeof(Line64));

        funcName->chars     = malloc(maxlength);

        // Hack Alert: In the case that we have too few funcInfo's, print
        // \nAnon???. Of course, we'll still intermittently crash later, but
        // when we don't, the output will look pretty.
        // Replace "if (funcInfo)" from rev 319 around this...
        if (funcInfo)
            funcName->length    = snprintf(funcName->chars, maxlength,
                "\n%s%d:\n", ANON_FUNC_BASE, funcInfo->genericFuncNum);
        else
            funcName->length    = snprintf(funcName->chars, maxlength,
                "\n%s???:\n", ANON_FUNC_BASE);

        InsertLineBefore(funcName, *ioLine, &iPlainLineListHead);
    }

    // Finally, assemble the new string.
    char    finalFormatCString[MAX_FORMAT_LENGTH];
    UInt32  formatMarker    = 0;

    if (needNewLine)
    {
        formatMarker++;
        finalFormatCString[0]   = '\n';
        finalFormatCString[1]   = 0;
    }
    else
        finalFormatCString[0]   = 0;

    if (iOpts.localOffsets)
        formatMarker += snprintf(&finalFormatCString[formatMarker],
            10, "%s", "%s %s");

    if (iLineOperandsCString[0])
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

    char    theFinalCString[MAX_LINE_LENGTH] = "";

    if (iOpts.localOffsets)
        snprintf(theFinalCString, MAX_LINE_LENGTH - 1,
            finalFormatCString, localOffsetString,
            addrSpaces, theAddressCString,
            instSpaces, theCodeCString,
            mnemSpaces, theMnemonicCString,
            opSpaces, iLineOperandsCString,
            commentSpaces, theCommentCString);
    else
        snprintf(theFinalCString, MAX_LINE_LENGTH - 1,
            finalFormatCString, theAddressCString,
            instSpaces, theCodeCString,
            mnemSpaces, theMnemonicCString,
            opSpaces, iLineOperandsCString,
            commentSpaces, theCommentCString);

    free((*ioLine)->chars);

    if (iOpts.separateLogicalBlocks && iEnteringNewBlock &&
        theFinalCString[0] != '\n')
    {
        (*ioLine)->length   = strlen(theFinalCString) + 1;
        (*ioLine)->chars    = malloc((*ioLine)->length + 1);
        (*ioLine)->chars[0] = '\n';
        strncpy(&(*ioLine)->chars[1], theFinalCString, (*ioLine)->length);
    }
    else
    {
        (*ioLine)->length   = strlen(theFinalCString);
        (*ioLine)->chars    = malloc((*ioLine)->length + 1);
        strncpy((*ioLine)->chars, theFinalCString, (*ioLine)->length + 1);
    }

    // The test above can fail even if mEnteringNewBlock was YES, so we
    // should reset it here instead.
    iEnteringNewBlock = NO;

    UpdateRegisters(*ioLine);
    PostProcessCodeLine(ioLine);

    // Possibly prepend a \n to the following line.
    if (CodeIsBlockJump((*ioLine)->info.code))
        iEnteringNewBlock = YES;
}

//  addressFromLine:
// ----------------------------------------------------------------------------

- (UInt64)addressFromLine: (const char*)inLine
{
    // sanity check
    if ((inLine[0] < '0' || inLine[0] > '9') &&
        (inLine[0] < 'a' || inLine[0] > 'f'))
        return 0;

    UInt64  theAddress  = 0;

    sscanf(inLine, "%016llx", &theAddress);
    return theAddress;
}

//  lineIsCode:
// ----------------------------------------------------------------------------
//  Line is code if first 16 chars are hex numbers and 17th is tab.

- (BOOL)lineIsCode: (const char*)inLine
{
    if (strlen(inLine) < 18)
        return NO;

    UInt16  i;

    for (i = 0 ; i < 16; i++)
    {
        if ((inLine[i] < '0' || inLine[i] > '9') &&
            (inLine[i] < 'a' || inLine[i] > 'f'))
            return NO;
    }

    return (inLine[16] == '\t');
}

//  chooseLine:
// ----------------------------------------------------------------------------
//  Subclasses may override.

- (void)chooseLine: (Line64**)ioLine
{}

#pragma mark -
//  printDataSections
// ----------------------------------------------------------------------------
//  Append data sections to output file.

- (BOOL)printDataSections
{
    FILE*   outFile = NULL;

    if (iOutputFilePath)
        outFile = fopen(UTF8STRING(iOutputFilePath), "a");
    else
        outFile = stdout;

    if (!outFile)
    {
        perror("otx: unable to open output file");
        return NO;
    }

    if (iDataSect.size)
    {
        if (fprintf(outFile, "\n(__DATA,__data) section\n") < 0)
        {
            perror("otx: unable to write to output file");
            return NO;
        }

        [self printDataSection: &iDataSect toFile: outFile];
    }

    if (iCoalDataSect.size)
    {
        if (fprintf(outFile, "\n(__DATA,__coalesced_data) section\n") < 0)
        {
            perror("otx: unable to write to output file");
            return NO;
        }

        [self printDataSection: &iCoalDataSect toFile: outFile];
    }

    if (iCoalDataNTSect.size)
    {
        if (fprintf(outFile, "\n(__DATA,__datacoal_nt) section\n") < 0)
        {
            perror("otx: unable to write to output file");
            return NO;
        }

        [self printDataSection: &iCoalDataNTSect toFile: outFile];
    }

    if (iOutputFilePath)
    {
        if (fclose(outFile) != 0)
        {
            perror("otx: unable to close output file");
            return NO;
        }
    }

    return YES;
}

//  printDataSection:toFile:
// ----------------------------------------------------------------------------

- (void)printDataSection: (section_info_64*)inSect
                  toFile: (FILE*)outFile;
{
    UInt32  i, j, k, bytesLeft;
    UInt32  theDataSize         = inSect->size;
    char    theLineCString[70];
    char*   theMachPtr          = (char*)iMachHeaderPtr;

    theLineCString[0]   = 0;

    for (i = 0; i < theDataSize; i += 16)
    {
        bytesLeft   = theDataSize - i;

        if (bytesLeft < 16) // last line
        {
            theLineCString[0]   = 0;
            snprintf(theLineCString,
                20 ,"%08x |", inSect->s.addr + i);

            unsigned char   theHexData[17]      = {0};
            unsigned char   theASCIIData[17]    = {0};

            memcpy(theHexData,
                (const void*)(theMachPtr + inSect->s.offset + i), bytesLeft);
            memcpy(theASCIIData,
                (const void*)(theMachPtr + inSect->s.offset + i), bytesLeft);

            j   = 10;

            for (k = 0; k < bytesLeft; k++)
            {
                if (!(k % 4))
                    theLineCString[j++] = 0x20;

                snprintf(&theLineCString[j], 4, "%02x", theHexData[k]);
                j += 2;

                if (theASCIIData[k] < 0x20 || theASCIIData[k] == 0x7f)
                    theASCIIData[k] = '.';
            }

            // Append spaces.
            for (; j < 48; j++)
                theLineCString[j]   = 0x20;

            // Append ASCII chars.
            snprintf(&theLineCString[j], 70, "%s\n", theASCIIData);
        }
        else    // first lines
        {           
            UInt32*         theHexPtr           = (UInt32*)
                (theMachPtr + inSect->s.offset + i);
            unsigned char   theASCIIData[17]    = {0};
            UInt8           j;

            memcpy(theASCIIData,
                (const void*)(theMachPtr + inSect->s.offset + i), 16);

            for (j = 0; j < 16; j++)
                if (theASCIIData[j] < 0x20 || theASCIIData[j] == 0x7f)
                    theASCIIData[j] = '.';

#if TARGET_RT_LITTLE_ENDIAN
            theHexPtr[0]    = OSSwapInt32(theHexPtr[0]);
            theHexPtr[1]    = OSSwapInt32(theHexPtr[1]);
            theHexPtr[2]    = OSSwapInt32(theHexPtr[2]);
            theHexPtr[3]    = OSSwapInt32(theHexPtr[3]);
#endif

            snprintf(theLineCString, sizeof(theLineCString),
                "%08x | %08x %08x %08x %08x  %s\n",
                inSect->s.addr + i,
                theHexPtr[0], theHexPtr[1], theHexPtr[2], theHexPtr[3],
                theASCIIData);
        }

        if (fprintf(outFile, "%s", theLineCString) < 0)
        {
            perror("otx: [ExeProcessor printDataSection:toFile:]: "
                "unable to write to output file");
            return;
        }
    }
}

#pragma mark -
//  selectorForMsgSend:fromLine:
// ----------------------------------------------------------------------------
//  Subclasses may override.

- (char*)selectorForMsgSend: (char*)outComment
                   fromLine: (Line64*)inLine
{
    return NULL;
}

#pragma mark -
//  insertMD5
// ----------------------------------------------------------------------------

- (void)insertMD5
{
    char        md5Line[MAX_MD5_LINE];
    char        finalLine[MAX_MD5_LINE];
    NSString*   md5CommandString    = [NSString stringWithFormat:
        @"md5 -q \"%@\"", [iOFile path]];
    FILE*       md5Pipe             = popen(UTF8STRING(md5CommandString), "r");

    if (!md5Pipe)
    {
        fprintf(stderr, "otx: unable to open md5 pipe\n");
        return;
    }

    // In CLI mode, fgets(3) fails with EINTR "Interrupted system call". The
    // fix is to temporarily block the offending signal. Since we don't know
    // which signal is offensive, block them all.

    // Block all signals.
    sigset_t    oldSigs, newSigs;

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
    if (sigprocmask(SIG_SETMASK, &oldSigs, NULL) == -1)
    {
        perror("otx: unable to restore signals");
        return;
    }

    if (pclose(md5Pipe) == -1)
    {
        fprintf(stderr, "otx: error closing md5 pipe\n");
        return;
    }

    char*   format      = NULL;
    char*   prefix      = "\nmd5: ";
    UInt32  finalLength = strlen(md5Line) + strlen(prefix);

    if (strchr(md5Line, '\n'))
    {
        format  = "%s%s";
    }
    else
    {
        format  = "%s%s\n";
        finalLength++;
    }

    snprintf(finalLine, finalLength + 1, format, prefix, md5Line);

    Line64* newLine = calloc(1, sizeof(Line64));

    newLine->length = strlen(finalLine);
    newLine->chars  = malloc(newLine->length + 1);
    strncpy(newLine->chars, finalLine, newLine->length + 1);

    InsertLineAfter(newLine, iPlainLineListHead, &iPlainLineListHead);
}

#pragma mark -
//  decodeMethodReturnType:output:
// ----------------------------------------------------------------------------

- (void)decodeMethodReturnType: (const char*)inTypeCode
                        output: (char*)outCString
{
    UInt32  theNextChar = 0;

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

//  getDescription:forType:
// ----------------------------------------------------------------------------
//  "filer types" defined in objc/objc-class.h, NSCoder.h, and
// http://developer.apple.com/documentation/DeveloperTools/gcc-3.3/gcc/Type-encoding.html

- (void)getDescription: (char*)ioCString
               forType: (const char*)inTypeCode
{
    if (!inTypeCode || !ioCString)
        return;

    char    theSuffixCString[50];
    UInt32  theNextChar = 0;
    UInt16  i           = 0;

/*
    char vs. BOOL

    data type       encoding
    —————————       ————————
    char            c
    BOOL            c
    char[100]       [100c]
    BOOL[100]       [100c]

    from <objc/objc.h>:
        typedef signed char     BOOL; 
        // BOOL is explicitly signed so @encode(BOOL) == "c" rather than "C" 
        // even if -funsigned-char is used.

    Ok, so BOOL is just a synonym for signed char, and the @encode directive
    can't be expected to desynonize that. Fair enough, but for our purposes,
    it would be nicer if BOOL was synonized to unsigned char instead.

    So, any occurence of 'c' may be a char or a BOOL. The best option I can
    see is to treat arrays as char arrays and atomic values as BOOL, and maybe
    let the user disagree via preferences. Since the data type of an array is
    decoded with a recursive call, we can use the following static variable
    for this purpose.

    As of otx 0.14b, letting the user override this behavior with a pref is
    left as an exercise for the reader.
*/
    static BOOL isArray = NO;

    // Convert '^^' prefix to '**' suffix.
    while (inTypeCode[theNextChar] == '^')
    {
        theSuffixCString[i++]   = '*';
        theNextChar++;
    }

    // Add the null terminator.
    theSuffixCString[i] = 0;
    i   = 0;

    char    theTypeCString[MAX_TYPE_STRING_LENGTH];

    theTypeCString[0]   = 0;

    // Now we can get at the basic type.
    switch (inTypeCode[theNextChar])
    {
        case '@':
        {
            if (inTypeCode[theNextChar + 1] == '"')
            {
                UInt32  classNameLength =
                    strlen(&inTypeCode[theNextChar + 2]);

                memcpy(theTypeCString, &inTypeCode[theNextChar + 2],
                    classNameLength - 1);

                // Add the null terminator.
                theTypeCString[classNameLength - 1] = 0;
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
        case 'q':   // not in objc-class.h
            strncpy(theTypeCString, "long long", 10);
            break;
        case 'Q':   // not in objc-class.h
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
        case '(':   // union- just copy the name
            while (inTypeCode[++theNextChar] != '=' &&
                   inTypeCode[theNextChar]   != ')' &&
                   inTypeCode[theNextChar]   != '<' &&
                   theNextChar < MAX_TYPE_STRING_LENGTH)
                theTypeCString[i++] = inTypeCode[theNextChar];

                // Add the null terminator.
                theTypeCString[i]   = 0;

            break;

        case '{':   // struct- just copy the name
            while (inTypeCode[++theNextChar] != '=' &&
                   inTypeCode[theNextChar]   != '}' &&
                   inTypeCode[theNextChar]   != '<' &&
                   theNextChar < MAX_TYPE_STRING_LENGTH)
                theTypeCString[i++] = inTypeCode[theNextChar];

                // Add the null terminator.
                theTypeCString[i]   = 0;

            break;

        case '[':   // array…   [12^f] <-> float*[12]
        {
            char    theArrayCCount[10]  = {0};

            while (inTypeCode[++theNextChar] >= '0' &&
                   inTypeCode[theNextChar]   <= '9')
                theArrayCCount[i++] = inTypeCode[theNextChar];

            // Recursive madness. See 'char vs. BOOL' note above.
            char    theCType[MAX_TYPE_STRING_LENGTH];

            theCType[0] = 0;

            isArray = YES;
            GetDescription(theCType, &inTypeCode[theNextChar]);
            isArray = NO;

            snprintf(theTypeCString, MAX_TYPE_STRING_LENGTH + 1, "%s[%s]",
                theCType, theArrayCCount);

            break;
        }

        default:
            strncpy(theTypeCString, "?", 2);

            break;
    }

    strncat(ioCString, theTypeCString, strlen(theTypeCString));

    if (theSuffixCString[0])
        strncat(ioCString, theSuffixCString, strlen(theSuffixCString));
}

#pragma mark -
//  entabLine:
// ----------------------------------------------------------------------------
//  A cheap and fast way to entab a line, assuming it contains no tabs already.
//  If tabs get added in the future, this WILL break. Single spaces are not
//  replaced with tabs, even when possible, since it would save no additional
//  bytes. Comments are not entabbed, as that would remove the user's ability
//  to search for them in the source code or a hex editor.

- (void)entabLine: (Line64*)ioLine;
{
    if (!ioLine || !ioLine->chars)
        return;

    // only need to do this math once...
    static UInt32   startOfComment  = 0;

    if (startOfComment == 0)
    {
        startOfComment  = iFieldWidths.address + iFieldWidths.instruction +
            iFieldWidths.mnemonic + iFieldWidths.operands;

        if (iOpts.localOffsets)
            startOfComment  += iFieldWidths.offset;
    }

    char    entabbedLine[MAX_LINE_LENGTH];
    UInt32  theOrigLength   = ioLine->length;

    // If 1st char is '\n', skip it.
    UInt32  firstChar   = (ioLine->chars[0] == '\n');
    UInt32  i;          // old line marker
    UInt32  j   = 0;    // new line marker

    if (firstChar)
    {
        j++;
        entabbedLine[0] = '\n';
        entabbedLine[1] = 0;
    }
    else
        entabbedLine[0] = 0;

    // Inspect 4 bytes at a time.
    for (i = firstChar; i < theOrigLength; i += 4)
    {
        // Don't entab comments.
        if (i >= (startOfComment + firstChar) - 4)
        {
            strncpy(&entabbedLine[j], &ioLine->chars[i],
                (theOrigLength - i) + 1);

            break;
        }

        // If fewer than 4 bytes remain, adding any tabs is pointless.
        if (i > theOrigLength - 4)
        {   // Copy the remainder and split.
            while (i < theOrigLength)
                entabbedLine[j++] = ioLine->chars[i++];

            // Add the null terminator.
            entabbedLine[j] = 0;

            break;
        }

        // If the 4th char is not a space, the first 3 chars don't matter.
        if (ioLine->chars[i + 3] == 0x20)   // 4th char is a space...
        {
            if (ioLine->chars[i + 2] == 0x20)   // 3rd char is a space...
            {
                if (ioLine->chars[i + 1] == 0x20)   // 2nd char is a space...
                {
                    if (ioLine->chars[i] == 0x20)   // all 4 chars are spaces!
                        entabbedLine[j++] = '\t';   // write a tab and split
                    else    // only the 1st char is not a space
                    {       // copy 1st char and tab
                        entabbedLine[j++] = ioLine->chars[i];
                        entabbedLine[j++] = '\t';
                    }
                }
                else    // 2nd char is not a space
                {       // copy 1st 2 chars and tab
                    entabbedLine[j++] = ioLine->chars[i];
                    entabbedLine[j++] = ioLine->chars[i + 1];
                    entabbedLine[j++] = '\t';
                }
            }
            else    // 3rd char is not a space
            {       // copy 1st 3 chars and tab
                entabbedLine[j++] = ioLine->chars[i];
                entabbedLine[j++] = ioLine->chars[i + 1];
                entabbedLine[j++] = ioLine->chars[i + 2];
                entabbedLine[j++] = '\t';
            }
        }
        else    // 4th char is not a space
        {       // copy all 4 chars
            memcpy(&entabbedLine[j], &ioLine->chars[i], 4);
            j += 4;
        }

        // Add the null terminator.
        entabbedLine[j] = 0;
    }

    // Replace the old C string with the new one.
    free(ioLine->chars);
    ioLine->length  = strlen(entabbedLine);
    ioLine->chars   = malloc(ioLine->length + 1);
    strncpy(ioLine->chars, entabbedLine, ioLine->length + 1);
}

//  getPointer:type:    (was get_pointer)
// ----------------------------------------------------------------------------
//  Convert a relative ptr to an absolute ptr. Return which data type is being
//  referenced in outType.

- (char*)getPointer: (UInt64)inAddr
               type: (UInt8*)outType
{
    if (inAddr == 0)
        return NULL;

    if (outType)
        *outType    = PointerType;

    char*   thePtr  = NULL;

            // (__TEXT,__cstring) (char*)
    if (inAddr >= iCStringSect.s.addr &&
        inAddr < iCStringSect.s.addr + iCStringSect.size)
    {
        thePtr = (iCStringSect.contents + (inAddr - iCStringSect.s.addr));

        // Make sure we're pointing to the beginning of a string,
        // not somewhere in the middle.
        if (*(thePtr - 1) != 0 && inAddr != iCStringSect.s.addr)
            thePtr  = NULL;
        // Check if this may be a Pascal string. Thanks, Metrowerks.
        else if (outType && strlen(thePtr) == thePtr[0] + 1)
            *outType    = PStringType;
    }
    else    // (__TEXT,__const) (Str255* sometimes)
    if (inAddr >= iConstTextSect.s.addr &&
        inAddr < iConstTextSect.s.addr + iConstTextSect.size)
    {
        thePtr  = (iConstTextSect.contents + (inAddr - iConstTextSect.s.addr));

        if (outType && strlen(thePtr) == thePtr[0] + 1)
            *outType    = PStringType;
        else
            thePtr  = NULL;
    }
    else    // (__TEXT,__literal4) (float)
    if (inAddr >= iLit4Sect.s.addr &&
        inAddr < iLit4Sect.s.addr + iLit4Sect.size)
    {
        thePtr  = (char*)(iLit4Sect.contents +
            (inAddr - iLit4Sect.s.addr));

        if (outType)
            *outType    = FloatType;
    }
    else    // (__TEXT,__literal8) (double)
    if (inAddr >= iLit8Sect.s.addr &&
        inAddr < iLit8Sect.s.addr + iLit8Sect.size)
    {
        thePtr  = (char*)(iLit8Sect.contents +
            (inAddr - iLit8Sect.s.addr));

        if (outType)
            *outType    = DoubleType;
    }

    if (thePtr)
        return thePtr;

            // (__IMPORT,__pointers) (cf_string_object*)
    if (inAddr >= iImpPtrSect.s.addr &&
        inAddr < iImpPtrSect.s.addr + iImpPtrSect.size)
    {
        thePtr  = (char*)(iImpPtrSect.contents +
            (inAddr - iImpPtrSect.s.addr));

        if (outType)
            *outType    = ImpPtrType;
    }

    if (thePtr)
        return thePtr;

            // (__DATA,__data) (char**)
    if (inAddr >= iDataSect.s.addr &&
        inAddr < iDataSect.s.addr + iDataSect.size)
    {
        thePtr = (char*)(iDataSect.contents + (inAddr - iDataSect.s.addr));

        UInt8 theType = DataGenericType;
        UInt64 theValue = *(UInt64*)thePtr;

        if (iSwapped)
            theValue = OSSwapInt64(theValue);

        if (theValue != 0)
        {
            theType = PointerType;

            static UInt32 recurseCount = 0;

            while (theType == PointerType)
            {
                recurseCount++;

                if (recurseCount > 5)
                {
                    theType = DataGenericType;
                    break;
                }

                thePtr = GetPointer(theValue, &theType);

                if (!thePtr)
                {
                    theType = DataGenericType;
                    break;
                }

                theValue = *(UInt64*)thePtr;
            }

            recurseCount = 0;
        }

        if (outType)
            *outType = theType;
    }
    else    // (__DATA,__const) (void*)
    if (inAddr >= iConstDataSect.s.addr &&
        inAddr < iConstDataSect.s.addr + iConstDataSect.size)
    {
        thePtr  = (char*)(iConstDataSect.contents +
            (inAddr - iConstDataSect.s.addr));

        if (outType)
        {
            UInt32  theID   = *(UInt32*)thePtr;

            if (iSwapped)
                theID   = OSSwapInt32(theID);

            if (theID == typeid_NSString)
                *outType    = OCStrObjectType;
            else
            {
                theID   = *(UInt32*)(thePtr + 4);

                if (iSwapped)
                    theID   = OSSwapInt32(theID);

                if (theID == typeid_NSString)
                    *outType    = CFStringType;
                else
                    *outType    = DataConstType;
            }
        }
    }
/*    else    // (__DATA,__objc_classlist)
    if (inAddr >= iObjcClassListSect.s.addr &&
        inAddr < iObjcClassListSect.s.addr + iObjcClassListSect.size)
    {
    }*/
    else    // (__DATA,__objc_classrefs)
    if (inAddr >= iObjcClassRefsSect.s.addr &&
        inAddr < iObjcClassRefsSect.s.addr + iObjcClassRefsSect.size)
    {
        if (inAddr % 8 == 0)
        {
            UInt64 classRef = *(UInt64*)(iObjcClassRefsSect.contents +
                (inAddr - iObjcClassRefsSect.s.addr));

            if (classRef != 0)
            {
                if (iSwapped)
                    classRef = OSSwapInt64(classRef);

                objc2_class_t swappedClass = *(objc2_class_t*)(iObjcClassRefsSect.contents +
                    (classRef - iObjcClassRefsSect.s.addr));

                if (iSwapped)
                    swap_objc2_class(&swappedClass);

                objc2_class_ro_t roData = *(objc2_class_ro_t*)(iDataSect.contents +
                    (swappedClass.data - iDataSect.s.addr));

                if (iSwapped)
                    roData.name = OSSwapInt64(roData.name);

                thePtr = GetPointer(roData.name, NULL);

                if (outType)
                    *outType = OCClassRefType;
            }
        }
    }
    else    // (__DATA,__objc_msgrefs)
    if (inAddr >= iObjcMsgRefsSect.s.addr &&
        inAddr < iObjcMsgRefsSect.s.addr + iObjcMsgRefsSect.size)
    {
        objc2_message_ref_t ref = *(objc2_message_ref_t*)(iObjcMsgRefsSect.contents +
            (inAddr - iObjcMsgRefsSect.s.addr));

        if (iSwapped)
            ref.sel = OSSwapInt64(ref.sel);

        thePtr = GetPointer(ref.sel, NULL);

        if (outType)
            *outType = OCMsgRefType;
    }
    else    // (__DATA,__objc_catlist)
    if (inAddr >= iObjcCatListSect.s.addr &&
        inAddr < iObjcCatListSect.s.addr + iObjcCatListSect.size)
    {
    }
    else    // (__DATA,__objc_superrefs)
    if (inAddr >= iObjcSuperRefsSect.s.addr &&
        inAddr < iObjcSuperRefsSect.s.addr + iObjcSuperRefsSect.size)
    {
        UInt64 superAddy = *(UInt64*)(iObjcSuperRefsSect.contents +
            (inAddr - iObjcSuperRefsSect.s.addr));

        if (iSwapped)
            superAddy = OSSwapInt64(superAddy);

        if (superAddy != 0)
        {
            objc2_class_t swappedClass = *(objc2_class_t*)(iDataSect.contents +
                (superAddy - iDataSect.s.addr));

            if (iSwapped)
                swap_objc2_class(&swappedClass);

            if (swappedClass.data != 0)
            {
                objc2_class_ro_t* roPtr = (objc2_class_ro_t*)(iDataSect.contents +
                    (swappedClass.data - iDataSect.s.addr));
                UInt64 namePtr = roPtr->name;

                if (iSwapped)
                    namePtr = OSSwapInt64(namePtr);

                if (namePtr != 0)
                {
                    thePtr = GetPointer(namePtr, NULL);

                    if (outType)
                        *outType = OCSuperRefType;
                }
            }
        }
    }
    else    // (__DATA,__objc_selrefs)
    if (inAddr >= iObjcSelRefsSect.s.addr &&
        inAddr < iObjcSelRefsSect.s.addr + iObjcSelRefsSect.size)
    {
        UInt64 selAddy = *(UInt64*)(iObjcSelRefsSect.contents +
            (inAddr - iObjcSelRefsSect.s.addr));

        if (iSwapped)
            selAddy = OSSwapInt64(selAddy);

        if (selAddy != 0)
        {
            thePtr = GetPointer(selAddy, NULL);

            if (outType)
                *outType = OCSelRefType;
        }
    }
    else
    if ((inAddr >= iObjcProtoRefsSect.s.addr &&    // (__DATA,__objc_protorefs)
        inAddr < iObjcProtoRefsSect.s.addr + iObjcProtoRefsSect.size) ||
        (inAddr >= iObjcProtoListSect.s.addr &&    // (__DATA,__objc_protolist)
        inAddr < iObjcProtoListSect.s.addr + iObjcProtoListSect.size))
    {
        UInt64 protoAddy;
        UInt8 tempType;

        if (inAddr >= iObjcProtoRefsSect.s.addr &&
            inAddr < iObjcProtoRefsSect.s.addr + iObjcProtoRefsSect.size)
        {
            protoAddy = *(UInt64*)(iObjcProtoRefsSect.contents +
                (inAddr - iObjcProtoRefsSect.s.addr));
            tempType = OCProtoRefType;
        }
        else
        {
            protoAddy = *(UInt64*)(iObjcProtoListSect.contents +
                (inAddr - iObjcProtoListSect.s.addr));
            tempType = OCProtoListType;
        }

        if (iSwapped)
            protoAddy = OSSwapInt64(protoAddy);

        if (protoAddy != 0 &&
            (protoAddy >= iDataSect.s.addr && protoAddy < (iDataSect.s.addr + iDataSect.size)))
        {
            objc2_protocol_t* proto = (objc2_protocol_t*)(iDataSect.contents +
                (protoAddy - iDataSect.s.addr));
            UInt64 protoName = proto->name;

            if (iSwapped)
                protoName = OSSwapInt64(protoName);

            if (protoName != 0)
            {
                thePtr = GetPointer(protoName, NULL);

                if (outType)
                    *outType = tempType;
            }
        }
    }
    else    // (__DATA,__cfstring) (cf_string_object*)
    if (inAddr >= iCFStringSect.s.addr &&
        inAddr < iCFStringSect.s.addr + iCFStringSect.size)
    {
        thePtr  = (char*)(iCFStringSect.contents +
            (inAddr - iCFStringSect.s.addr));

        if (outType)
            *outType    = CFStringType;
    }
    else    // (__DATA,__nl_symbol_ptr) (cf_string_object*)
    if (inAddr >= iNLSymSect.s.addr &&
        inAddr < iNLSymSect.s.addr + iNLSymSect.size)
    {
        thePtr  = (char*)(iNLSymSect.contents +
            (inAddr - iNLSymSect.s.addr));

        if (outType)
            *outType    = NLSymType;
    }
    else    // (__DATA,__dyld) (function ptr)
    if (inAddr >= iDyldSect.s.addr &&
        inAddr < iDyldSect.s.addr + iDyldSect.size)
    {
        thePtr  = (char*)(iDyldSect.contents +
            (inAddr - iDyldSect.s.addr));

        if (outType)
            *outType    = DYLDType;
    }

    // should implement these if they ever contain CFStrings or NSStrings
/*  else    // (__DATA, __coalesced_data) (?)
    if (localAddy >= mCoalDataSect.s.addr &&
        localAddy < mCoalDataSect.s.addr + mCoalDataSect.size)
    {
    }
    else    // (__DATA, __datacoal_nt) (?)
    if (localAddy >= mCoalDataNTSect.s.addr &&
        localAddy < mCoalDataNTSect.s.addr + mCoalDataNTSect.size)
    {
    }*/

    return thePtr;
}

#pragma mark -
//  speedyDelivery
// ----------------------------------------------------------------------------

- (void)speedyDelivery
{
    GetDescription                  = GetDescription64FuncType
        [self methodForSelector: GetDescriptionSel];
    LineIsCode                      = LineIsCode64FuncType
        [self methodForSelector: LineIsCodeSel];
    LineIsFunction                  = LineIsFunction64FuncType
        [self methodForSelector: LineIsFunctionSel];
    CodeIsBlockJump                 = CodeIsBlockJump64FuncType
        [self methodForSelector: CodeIsBlockJumpSel];
    AddressFromLine                 = AddressFromLine64FuncType
        [self methodForSelector: AddressFromLineSel];
    CodeFromLine                    = CodeFromLine64FuncType
        [self methodForSelector: CodeFromLineSel];
    CheckThunk                      = CheckThunk64FuncType
        [self methodForSelector : CheckThunkSel];
    ProcessLine                     = ProcessLine64FuncType
        [self methodForSelector: ProcessLineSel];
    ProcessCodeLine                 = ProcessCodeLine64FuncType
        [self methodForSelector: ProcessCodeLineSel];
    PostProcessCodeLine             = PostProcessCodeLine64FuncType
        [self methodForSelector: PostProcessCodeLineSel];
    ChooseLine                      = ChooseLine64FuncType
        [self methodForSelector: ChooseLineSel];
    EntabLine                       = EntabLine64FuncType
        [self methodForSelector: EntabLineSel];
    GetPointer                      = GetPointer64FuncType
        [self methodForSelector: GetPointerSel];
    CommentForLine                  = CommentForLine64FuncType
        [self methodForSelector: CommentForLineSel];
    CommentForSystemCall            = CommentForSystemCall64FuncType
        [self methodForSelector: CommentForSystemCallSel];
    CommentForMsgSendFromLine       = CommentForMsgSendFromLine64FuncType
        [self methodForSelector: CommentForMsgSendFromLineSel];
    SelectorForMsgSend              = SelectorForMsgSend64FuncType
        [self methodForSelector: SelectorForMsgSendSel];
    ResetRegisters                  = ResetRegisters64FuncType
        [self methodForSelector: ResetRegistersSel];
    UpdateRegisters                 = UpdateRegisters64FuncType
        [self methodForSelector: UpdateRegistersSel];
    RestoreRegisters                = RestoreRegisters64FuncType
        [self methodForSelector: RestoreRegistersSel];
    SendTypeFromMsgSend             = SendTypeFromMsgSend64FuncType
        [self methodForSelector: SendTypeFromMsgSendSel];
    PrepareNameForDemangling        = PrepareNameForDemangling64FuncType
        [self methodForSelector: PrepareNameForDemanglingSel];
    GetObjcClassPtrFromMethod       = GetObjcClassPtrFromMethod64FuncType
        [self methodForSelector: GetObjcClassPtrFromMethodSel];
    GetObjcMethodFromAddress        = GetObjcMethodFromAddress64FuncType
        [self methodForSelector: GetObjcMethodFromAddressSel];
    GetObjcClassFromName            = GetObjcClassFromName64FuncType
        [self methodForSelector: GetObjcClassFromNameSel];
    GetObjcClassPtrFromName         = GetObjcClassPtrFromName64FuncType
        [self methodForSelector: GetObjcClassPtrFromNameSel];
    GetObjcDescriptionFromObject    = GetObjcDescriptionFromObject64FuncType
        [self methodForSelector: GetObjcDescriptionFromObjectSel];
    GetObjcMetaClassFromClass       = GetObjcMetaClassFromClass64FuncType
        [self methodForSelector: GetObjcMetaClassFromClassSel];
    InsertLineBefore                = InsertLineBefore64FuncType
        [self methodForSelector: InsertLineBeforeSel];
    InsertLineAfter                 = InsertLineAfter64FuncType
        [self methodForSelector: InsertLineAfterSel];
    ReplaceLine                     = ReplaceLine64FuncType
        [self methodForSelector: ReplaceLineSel];
    DeleteLinesBefore               = DeleteLinesBefore64FuncType
        [self methodForSelector: DeleteLinesBeforeSel];
    FindSymbolByAddress             = FindSymbolByAddress64FuncType
        [self methodForSelector: FindSymbolByAddressSel];
    FindClassMethodByAddress        = FindClassMethodByAddress64FuncType
        [self methodForSelector: FindClassMethodByAddressSel];
    FindCatMethodByAddress          = FindCatMethodByAddress64FuncType
        [self methodForSelector: FindCatMethodByAddressSel];
    FindIvar                        = FindIvar64FuncType
        [self methodForSelector: FindIvarSel];
}

#ifdef OTX_DEBUG
//  printSymbol:
// ----------------------------------------------------------------------------
//  Used for symbol debugging.

- (void)printSymbol: (nlist)inSym
{
    fprintf(stderr, "----------------\n\n");
    fprintf(stderr, " n_strx = 0x%08x\n", inSym.n_un.n_strx);
    fprintf(stderr, " n_type = 0x%02x\n", inSym.n_type);
    fprintf(stderr, " n_sect = 0x%02x\n", inSym.n_sect);
    fprintf(stderr, " n_desc = 0x%04x\n", inSym.n_desc);
    fprintf(stderr, "n_value = 0x%08x (%u)\n\n", inSym.n_value, inSym.n_value);

    if ((inSym.n_type & N_STAB) != 0)
    {   // too complicated, see <mach-o/stab.h>
        fprintf(stderr, "STAB symbol\n");
    }
    else    // not a STAB
    {
        if ((inSym.n_type & N_PEXT) != 0)
            fprintf(stderr, "Private external symbol\n\n");
        else if ((inSym.n_type & N_EXT) != 0)
            fprintf(stderr, "External symbol\n\n");

        UInt8   theNType    = inSym.n_type & N_TYPE;
        UInt16  theRefType  = inSym.n_desc & REFERENCE_TYPE;

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

//  printBlocks:
// ----------------------------------------------------------------------------
//  Used for block debugging. Sublclasses may override.

- (void)printBlocks: (UInt32)inFuncIndex;
{}
#endif  // OTX_DEBUG

@end
