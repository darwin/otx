/*
    X86Processor.m

    A subclass of Exe32Processor that handles x86-specific issues.

    This file is in the public domain.
*/

#import <Cocoa/Cocoa.h>

#import "X86Processor.h"
#import "ArchSpecifics.h"
#import "ListUtils.h"
#import "ObjcAccessors.h"
#import "ObjectLoader.h"
#import "SyscallStrings.h"
#import "UserDefaultKeys.h"

#define REUSE_BLOCKS    1

@implementation X86Processor

//  initWithURL:controller:options:
// ----------------------------------------------------------------------------

- (id)initWithURL: (NSURL*)inURL
       controller: (id)inController
          options: (ProcOptions*)inOptions;
{
    if ((self = [super initWithURL: inURL
        controller: inController options: inOptions]))
    {
        strncpy(iArchString, "i386", 5);

        iArchSelector               = CPU_TYPE_I386;
        iFieldWidths.offset         = 8;
        iFieldWidths.address        = 10;
        iFieldWidths.instruction    = 24;   // 15 bytes is the real max, but this works
        iFieldWidths.mnemonic       = 12;   // repnz/scasb
        iFieldWidths.operands       = 30;   // 0x00000000(%eax,%eax,4),%xmm0
    }

    return self;
}

//  dealloc
// ----------------------------------------------------------------------------

- (void)dealloc
{
    if (iLocalSelves)
    {
        free(iLocalSelves);
        iLocalSelves    = nil;
    }

    if (iLocalVars)
    {
        free(iLocalVars);
        iLocalVars  = nil;
    }

    [super dealloc];
}

//  loadDyldDataSection:
// ----------------------------------------------------------------------------

- (void)loadDyldDataSection: (section*)inSect
{
    [super loadDyldDataSection: inSect];

    if (!iAddrDyldStubBindingHelper)
        return;

    iAddrDyldFuncLookupPointer  = iAddrDyldStubBindingHelper + 12;
}

//  codeFromLine:
// ----------------------------------------------------------------------------

- (void)codeFromLine: (Line*)inLine
{
    UInt8   theInstLength   = 0;
    UInt32  thisAddy        = inLine->info.address;
    Line*   nextLine        = inLine->next;

    // Try to find next code line.
    while (nextLine)
    {
        if (![self lineIsCode: nextLine->chars])
            nextLine    = nextLine->next;
        else
            break;
    }

    // This instruction size is either the difference of 2 addys or the
    // difference of this addy from the end of the section.
    UInt32  nextAddy    = iEndOfText;

    if (nextLine)
    {
        UInt32  newNextAddy = AddressFromLine(nextLine->chars);

        // I've never seen a valid instruction longer than 12 bytes, but
        // encrypted code can contain invalid instructions up to 14 bytes long.
        if (newNextAddy > thisAddy && newNextAddy <= thisAddy + 14)
            nextAddy    = newNextAddy;
    }

    theInstLength   = nextAddy - thisAddy;

    // Fetch the instruction.
    unsigned char   charData[14]        = {0};
    char            formatString[50];
    char*           theMachPtr          = (char*)iMachHeaderPtr;
    char*           byteFormat          = "%02x";
    UInt8           byteFormatLength    = 4;    // hardcoded for speed
    UInt8           formatMarker        = 0;
    UInt8           i;

    for (i = 0; i < theInstLength; i++)
    {
        charData[i] = (iMachHeader.filetype == MH_OBJECT) ?
            *(unsigned char*)(theMachPtr + (thisAddy + iTextOffset) + i) :
            *(unsigned char*)(theMachPtr + (thisAddy - iTextOffset) + i);
        memcpy(&formatString[formatMarker], byteFormat, byteFormatLength);
        formatMarker    += byteFormatLength;
    }

    // Add the null terminator.
    formatString[formatMarker]  = 0;

    snprintf(inLine->info.code, 25, formatString,
        charData[0], charData[1], charData[2], charData[3], charData[4],
        charData[5], charData[6], charData[7], charData[8], charData[9],
        charData[10], charData[11], charData[12], charData[13]);
}

//  checkThunk:
// ----------------------------------------------------------------------------

- (void)checkThunk: (Line*)inLine
{
    if (!inLine || !inLine->prev || inLine->info.code[2])
        return;

    if (inLine->info.code[0] != 'c' ||
        inLine->info.code[1] != '3')
        return;

    UInt32      theInstruction  = strtoul(inLine->prev->info.code, nil, 16);
    ThunkInfo   theThunk        = {inLine->prev->info.address, NO_REG};

    switch (theInstruction)
    {
        case 0x8b0424:  // movl (%esp,1), %eax
            theThunk.reg    = EAX;
            break;

        case 0x8b0c24:  // movl (%esp,1), %ecx
            theThunk.reg    = ECX;
            break;

        case 0x8b1424:  // movl (%esp,1), %edx
            theThunk.reg    = EDX;
            break;

        case 0x8b1c24:  // movl (%esp,1), %ebx
            theThunk.reg    = EBX;
            break;

        default:
            return;
    }

    // Store a thunk.
    iNumThunks++;
    iThunks = realloc(iThunks,
        iNumThunks * sizeof(ThunkInfo));
    iThunks[iNumThunks - 1] = theThunk;

    // Recognize it as a function.
    inLine->prev->info.isFunction = YES;

    if (inLine->prev->alt)
        inLine->prev->alt->info.isFunction = YES;
}

//  getThunkInfo:forLine:
// ----------------------------------------------------------------------------
//  Determine whether this line is a call to a get_thunk routine. If so,
//  outRegNum specifies which register is being thunkified.

- (BOOL)getThunkInfo: (ThunkInfo*)outInfo
             forLine: (Line*)inLine
{
    if (!inLine)
    {
        fprintf(stderr, "otx: [X86Processor getThunkInfo:forLine:] "
            "nil inLine\n");
        return NO;
    }

    if (!inLine->next)
        return NO;

    if (!outInfo)
    {
        fprintf(stderr, "otx: [X86Processor getThunkInfo:forLine:] "
            "nil outInfo\n");
        return NO;
    }

    if (!iThunks)
        return NO;

    UInt8       opcode;

    sscanf(inLine->info.code, "%02hhx", &opcode);

    if (opcode != 0xe8) // calll
        return NO;

    BOOL    isThunk = NO;
    UInt32  imm, target, i;

    sscanf(&inLine->info.code[2], "%08x", &imm);
    imm = OSSwapInt32(imm);
    target  = imm + inLine->next->info.address;

    for (i = 0; i < iNumThunks; i++)
    {
        if (iThunks[i].address != target)
            continue;

        *outInfo    = iThunks[i];
        isThunk     = YES;
        break;
    }

    return isThunk;
}

#pragma mark -
//  commentForLine:
// ----------------------------------------------------------------------------

- (void)commentForLine: (Line*)inLine;
{
    char*   theDummyPtr = nil;
    char*   theSymPtr   = nil;
    UInt32  localAddy   = 0;
    UInt32  targetAddy  = 0;
    UInt8   modRM       = 0;
    UInt8   opcode;

    sscanf(inLine->info.code, "%02hhx", &opcode);
    iLineCommentCString[0]  = 0;

    switch (opcode)
    {
        case 0x0f:  // 2-byte and SSE opcodes   **add sysenter support here
        {
            if (inLine->info.code[2] == '2' &&
                inLine->info.code[3] == 'e')    // ucomiss
            {
                // sscanf interprets source values as big-endian, regardless of
                // host architecture. If source value is little-endian, as in x86
                // instructions, we must always swap.
                sscanf(&inLine->info.code[6], "%08x", &localAddy);
                localAddy   = OSSwapInt32(localAddy);

                theDummyPtr = GetPointer(localAddy, nil);

                if (theDummyPtr)
                {
                    UInt32  theInt32    = *(UInt32*)theDummyPtr;

                    theInt32    = OSSwapLittleToHostInt32(theInt32);
                    snprintf(iLineCommentCString, 30, "%G", *(float*)&theInt32);
                }
            }
            else if (inLine->info.code[2] == '8' &&
                     inLine->info.code[3] == '4')   // jcc
            {
                if (!inLine->next)
                    break;

                SInt32  targetOffset;

                sscanf(&inLine->info.code[4], "%08x", &targetOffset);
                targetOffset    = OSSwapInt32(targetOffset);
                targetAddy  = inLine->next->info.address + targetOffset;

                // Search current FunctionInfo for blocks that start at this address.
                FunctionInfo*   funcInfo    =
                    &iFuncInfos[iCurrentFuncInfoIndex];

                if (!funcInfo->blocks)
                    break;

                UInt32  i;

                for (i = 0; i < funcInfo->numBlocks; i++)
                {
                    if (funcInfo->blocks[i].beginAddress != targetAddy)
                        continue;

                    if (funcInfo->blocks[i].isEpilog)
                        snprintf(iLineCommentCString, 8, "return;");

                    break;
                }
            }

            break;
        }

        case 0x3c:  // cmpb imm8,al
        {
            UInt8   imm;

            sscanf(&inLine->info.code[2], "%02hhx", &imm);

            // Check for a single printable 7-bit char.
            if (imm >= 0x20 && imm < 0x7f)
                snprintf(iLineCommentCString, 4, "'%c'", imm);

            break;
        }

        case 0x66:
            if (inLine->info.code[2] != '0' ||
                inLine->info.code[3] != 'f' ||
                inLine->info.code[4] != '2' ||
                inLine->info.code[5] != 'e')    // ucomisd
                break;

            sscanf(&inLine->info.code[8], "%08x", &localAddy);
            localAddy   = OSSwapInt32(localAddy);

            theDummyPtr = GetPointer(localAddy, nil);

            if (theDummyPtr)
            {
                UInt64  theInt64    = *(UInt64*)theDummyPtr;

                theInt64    = OSSwapLittleToHostInt64(theInt64);
                snprintf(iLineCommentCString, 30, "%lG", *(double*)&theInt64);
            }

            break;

        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: 
        case 0x76: case 0x77: case 0x78: case 0x79: case 0x7a: case 0x7b: 
        case 0x7c: case 0x7d: case 0x7e: case 0xe3: // jcc
        case 0xeb:  // jmp
        {   // FIXME: this doesn't recognize tail calls.
            if (!inLine->next)
                break;

            SInt8   simm;

            sscanf(&inLine->info.code[2], "%02hhx", &simm);
            targetAddy  = inLine->next->info.address + simm;

            // Search current FunctionInfo for blocks that start at this address.
            FunctionInfo*   funcInfo    =
                &iFuncInfos[iCurrentFuncInfoIndex];

            if (!funcInfo->blocks)
                break;

            UInt32  i;

            for (i = 0; i < funcInfo->numBlocks; i++)
            {
                if (funcInfo->blocks[i].beginAddress != targetAddy)
                    continue;

                if (funcInfo->blocks[i].isEpilog)
                    snprintf(iLineCommentCString, 8, "return;");

                break;
            }

            break;
        }

        // immediate group 1 - add, sub, cmp etc
        case 0x80:  // imm8,r8
        case 0x83:  // imm8,r32
        {
            sscanf(&inLine->info.code[2], "%02hhx", &modRM);

            // In immediate group 1 we only want cmpb
            if (OPEXT(modRM) != 7)
                break;

            UInt8   imm;
            UInt8   immOffset   = 4;

            if (HAS_DISP8(modRM))
                immOffset   +=  2;

            sscanf(&inLine->info.code[immOffset], "%02hhx", &imm);

            if (iRegInfos[REG2(modRM)].classPtr)    // address relative to class
            {
                if (!iRegInfos[REG2(modRM)].isValid)
                    break;

                // Ignore the 4th addressing mode
                if (MOD(modRM) == MODx)
                    break;

                objc_ivar   theIvar         = {0};
                objc_class  swappedClass    =
                    *iRegInfos[REG2(modRM)].classPtr;

                #if __BIG_ENDIAN__
                    swap_objc_class(&swappedClass);
                #endif

                if (!iIsInstanceMethod)
                {
                    if (!GetObjcMetaClassFromClass(
                        &swappedClass, &swappedClass))
                        break;

                    #if __BIG_ENDIAN__
                        swap_objc_class(&swappedClass);
                    #endif
                }

                sscanf(&inLine->info.code[4], "%02hhx", &immOffset);

                if (!FindIvar(&theIvar, &swappedClass, immOffset))
                    break;

                theSymPtr   = GetPointer(
                    (UInt32)theIvar.ivar_name, nil);

                if (theSymPtr)
                {
                    if (iOpts.variableTypes)
                    {
                        char    theTypeCString[MAX_TYPE_STRING_LENGTH];

                        theTypeCString[0]   = 0;

                        GetDescription(theTypeCString,
                            GetPointer((UInt32)theIvar.ivar_type, nil));
                        snprintf(iLineCommentCString,
                            MAX_COMMENT_LENGTH - 1, "(%s)%s",
                            theTypeCString, theSymPtr);
                    }
                    else
                        snprintf(iLineCommentCString,
                            MAX_COMMENT_LENGTH - 1, "%s",
                            theSymPtr);
                }
            }
            else
                // Check for a single printable 7-bit char.
                if (imm >= 0x20 && imm < 0x7f)
                    snprintf(iLineCommentCString, 4, "'%c'", imm);

            break;
        }

        case 0x2b:  // subl r/m32,r32
        case 0x3b:  // cmpl r/m32,r32
        case 0x81:  // immediate group 1 - imm32,r32
        case 0x88:  // movb r8,r/m8
        case 0x89:  // movl r32,r/m32
        case 0x8b:  // movl r/m32,r32
        case 0xc6:  // movb imm8,r/m32
            sscanf(&inLine->info.code[2], "%02hhx", &modRM);

            // In immediate group 1 we only want cmpl
            if (opcode == 0x81 && OPEXT(modRM) != 7)
                break;

            if (MOD(modRM) == MODimm)   // 1st addressing mode
            {
                if (RM(modRM) == DISP32)
                {
                    sscanf(&inLine->info.code[4], "%08x", &localAddy);
                    localAddy   = OSSwapInt32(localAddy);
                }
            }
            else
            {
                if (iRegInfos[REG2(modRM)].classPtr)    // address relative to class
                {
                    if (!iRegInfos[REG2(modRM)].isValid)
                        break;

                    // Ignore the 4th addressing mode
                    if (MOD(modRM) == MODx)
                        break;

                    objc_ivar   theIvar         = {0};
                    objc_class  swappedClass    =
                        *iRegInfos[REG2(modRM)].classPtr;

                    #if __BIG_ENDIAN__
                        swap_objc_class(&swappedClass);
                    #endif

                    if (!iIsInstanceMethod)
                    {
                        if (!GetObjcMetaClassFromClass(
                            &swappedClass, &swappedClass))
                            break;

                        #if __BIG_ENDIAN__
                            swap_objc_class(&swappedClass);
                        #endif
                    }

                    if (MOD(modRM) == MOD8)
                    {
                        UInt8   theSymOffset;

                        sscanf(&inLine->info.code[4], "%02hhx", &theSymOffset);

                        if (!FindIvar(&theIvar, &swappedClass, theSymOffset))
                            break;
                    }
                    else if (MOD(modRM) == MOD32)
                    {
                        UInt32  theSymOffset;

                        sscanf(&inLine->info.code[4], "%08x", &theSymOffset);
                        theSymOffset    = OSSwapInt32(theSymOffset);

                        if (!FindIvar(&theIvar, &swappedClass, theSymOffset))
                            break;
                    }

                    theSymPtr   = GetPointer(
                        (UInt32)theIvar.ivar_name, nil);

                    if (theSymPtr)
                    {
                        if (iOpts.variableTypes)
                        {
                            char    theTypeCString[MAX_TYPE_STRING_LENGTH];

                            theTypeCString[0]   = 0;

                            GetDescription(theTypeCString,
                                GetPointer((UInt32)theIvar.ivar_type, nil));
                            snprintf(iLineCommentCString,
                                MAX_COMMENT_LENGTH - 1, "(%s)%s",
                                theTypeCString, theSymPtr);
                        }
                        else
                            snprintf(iLineCommentCString,
                                MAX_COMMENT_LENGTH - 1, "%s",
                                theSymPtr);
                    }
                }
                else if (MOD(modRM) == MOD32)   // absolute address
                {
                    if (HAS_SIB(modRM))
                        break;

                    if (REG2(modRM) == iCurrentThunk &&
                        iRegInfos[iCurrentThunk].isValid)
                    {
                        UInt32  imm;

                        sscanf(&inLine->info.code[4], "%08x", &imm);
                        imm = OSSwapInt32(imm);

                        localAddy   =
                            iRegInfos[iCurrentThunk].value + imm;
                    }
                    else
                    {
                        sscanf(&inLine->info.code[4], "%08x", &localAddy);
                        localAddy   = OSSwapInt32(localAddy);
                    }
                }
            }

            break;

        case 0x8d:  // leal
            sscanf(&inLine->info.code[2], "%02hhx", &modRM);

            if (iRegInfos[REG2(modRM)].classPtr)    // address relative to class
            {
                if (!iRegInfos[REG2(modRM)].isValid)
                    break;

                // Ignore the 1st and 4th addressing modes
                if (MOD(modRM) == MODimm || MOD(modRM) == MODx)
                    break;

                objc_ivar   theIvar         = {0};
                objc_class  swappedClass    =
                    *iRegInfos[REG2(modRM)].classPtr;

                #if __BIG_ENDIAN__
                    swap_objc_class(&swappedClass);
                #endif

                if (!iIsInstanceMethod)
                {
                    if (!GetObjcMetaClassFromClass(
                        &swappedClass, &swappedClass))
                        break;

                    #if __BIG_ENDIAN__
                        swap_objc_class(&swappedClass);
                    #endif
                }

                if (MOD(modRM) == MOD8)
                {
                    UInt8   theSymOffset;

                    sscanf(&inLine->info.code[4], "%02hhx", &theSymOffset);

                    if (!FindIvar(&theIvar, &swappedClass, theSymOffset))
                        break;
                }
                else if (MOD(modRM) == MOD32)
                {
                    UInt32  theSymOffset;

                    sscanf(&inLine->info.code[4], "%08x", &theSymOffset);
                    theSymOffset    = OSSwapInt32(theSymOffset);

                    if (!FindIvar(&theIvar, &swappedClass, theSymOffset))
                        break;
                }

                theSymPtr   = GetPointer(
                    (UInt32)theIvar.ivar_name, nil);

                if (theSymPtr)
                {
                    if (iOpts.variableTypes)
                    {
                        char    theTypeCString[MAX_TYPE_STRING_LENGTH];

                        theTypeCString[0]   = 0;

                        GetDescription(theTypeCString,
                            GetPointer((UInt32)theIvar.ivar_type, nil));
                        snprintf(iLineCommentCString,
                            MAX_COMMENT_LENGTH - 1, "(%s)%s",
                            theTypeCString, theSymPtr);
                    }
                    else
                        snprintf(iLineCommentCString,
                            MAX_COMMENT_LENGTH - 1, "%s",
                            theSymPtr);
                }
            }
            else if (REG2(modRM) == iCurrentThunk)
            {
                UInt32  imm;

                sscanf(&inLine->info.code[4], "%08x", &imm);
                imm = OSSwapInt32(imm);

                localAddy   = iRegInfos[iCurrentThunk].value + imm;
            }
            else
            {
                sscanf(&inLine->info.code[4], "%08x", &localAddy);
                localAddy   = OSSwapInt32(localAddy);
            }

            break;

        case 0xa1:  // movl moffs32,r32
        case 0xa3:  // movl r32,moffs32
            sscanf(&inLine->info.code[2], "%08x", &localAddy);
            localAddy   = OSSwapInt32(localAddy);

            break;

        case 0xb0:  // movb imm8,%al
        case 0xb1:  // movb imm8,%cl
        case 0xb2:  // movb imm8,%dl
        case 0xb3:  // movb imm8,%bl
        case 0xb4:  // movb imm8,%ah
        case 0xb5:  // movb imm8,%ch
        case 0xb6:  // movb imm8,%dh
        case 0xb7:  // movb imm8,%bh
        {
            UInt8   imm;

            sscanf(&inLine->info.code[2], "%02hhx", &imm);

            // Check for a single printable 7-bit char.
            if (imm >= 0x20 && imm < 0x7f)
                snprintf(iLineCommentCString, 4, "'%c'", imm);

            break;
        }

        case 0xb8:  // movl imm32,%eax
        case 0xb9:  // movl imm32,%ecx
        case 0xba:  // movl imm32,%edx
        case 0xbb:  // movl imm32,%ebx
        case 0xbc:  // movl imm32,%esp
        case 0xbd:  // movl imm32,%ebp
        case 0xbe:  // movl imm32,%esi
        case 0xbf:  // movl imm32,%edi
            sscanf(&inLine->info.code[2], "%08x", &localAddy);
            localAddy   = OSSwapInt32(localAddy);

            // Check for a four char code.
            if (localAddy >= 0x20202020 && localAddy < 0x7f7f7f7f)
            {
                char*   fcc = (char*)&localAddy;

                if (fcc[0] >= 0x20 && fcc[0] < 0x7f &&
                    fcc[1] >= 0x20 && fcc[1] < 0x7f &&
                    fcc[2] >= 0x20 && fcc[2] < 0x7f &&
                    fcc[3] >= 0x20 && fcc[3] < 0x7f)
                {
                    #if __LITTLE_ENDIAN__   // reversed on purpose
                        localAddy   = OSSwapInt32(localAddy);
                    #endif

                    snprintf(iLineCommentCString,
                        7, "'%.4s'", fcc);
                }
            }
            else    // Check for a single printable 7-bit char.
            if (localAddy >= 0x20 && localAddy < 0x7f)
            {
                snprintf(iLineCommentCString, 4, "'%c'", localAddy);
            }

            break;

        case 0xc7:  // movl imm32,r/m32
        {
            sscanf(&inLine->info.code[2], "%02hhx", &modRM);

            if (iRegInfos[REG2(modRM)].classPtr)    // address relative to class
            {
                if (!iRegInfos[REG2(modRM)].isValid)
                    break;

                // Ignore the 1st and 4th addressing modes
                if (MOD(modRM) == MODimm || MOD(modRM) == MODx)
                    break;

                UInt8   immOffset                       = 4;
                char    fcc[7]                          = {0};

                if (HAS_DISP8(modRM))
                    immOffset   += 2;
                else if (HAS_REL_DISP32(modRM))
                    immOffset   += 8;

                if (HAS_SIB(modRM))
                    immOffset   += 2;

                objc_ivar   theIvar         = {0};
                objc_class  swappedClass    =
                    *iRegInfos[REG2(modRM)].classPtr;

                #if __BIG_ENDIAN__
                    swap_objc_class(&swappedClass);
                #endif

                if (!iIsInstanceMethod)
                {
                    if (!GetObjcMetaClassFromClass(
                        &swappedClass, &swappedClass))
                        break;

                    #if __BIG_ENDIAN__
                        swap_objc_class(&swappedClass);
                    #endif
                }

                if (MOD(modRM) == MOD8)
                {
                    UInt8   theSymOffset;

                    // offset precedes immediate value, subtract
                    // sizeof(UInt8) * 2
                    sscanf(&inLine->info.code[immOffset - 2], "%02hhx", &theSymOffset);

                    if (!FindIvar(&theIvar, &swappedClass, theSymOffset))
                        break;
                }
                else if (MOD(modRM) == MOD32)
                {
                    UInt32  imm;
                    UInt32  theSymOffset;

                    sscanf(&inLine->info.code[immOffset], "%08x", &imm);
                    imm = OSSwapInt32(imm);

                    // offset precedes immediate value, subtract
                    // sizeof(UInt32) * 2
                    sscanf(&inLine->info.code[immOffset - 8], "%08x", &theSymOffset);
                    theSymOffset    = OSSwapInt32(theSymOffset);

                    // Check for a four char code.
                    if (imm >= 0x20202020 && imm < 0x7f7f7f7f)
                    {
                        char*   tempFCC = (char*)&imm;

                        if (tempFCC[0] >= 0x20 && tempFCC[0] < 0x7f &&
                            tempFCC[1] >= 0x20 && tempFCC[1] < 0x7f &&
                            tempFCC[2] >= 0x20 && tempFCC[2] < 0x7f &&
                            tempFCC[3] >= 0x20 && tempFCC[3] < 0x7f)
                        {
                            #if __LITTLE_ENDIAN__   // reversed on purpose
                                imm = OSSwapInt32(imm);
                            #endif

                            snprintf(fcc, 7, "'%.4s'", tempFCC);
                        }
                    }
                    else    // Check for a single printable 7-bit char.
                    if (imm >= 0x20 && imm < 0x7f)
                    {
                        snprintf(fcc, 4, "'%c'", imm);
                    }

                    FindIvar(&theIvar, &swappedClass, theSymOffset);
                }

                theSymPtr   = GetPointer(
                    (UInt32)theIvar.ivar_name, nil);

                char    tempComment[MAX_COMMENT_LENGTH];

                tempComment[0]  = 0;

                // copy four char code and/or var name to comment.
                if (fcc[0])
                    strncpy(tempComment, fcc, strlen(fcc) + 1);

                if (theSymPtr)
                {
                    if (fcc[0])
                        strncat(tempComment, " ", 2);

                    UInt32  tempCommentLength   = strlen(tempComment);

                    if (iOpts.variableTypes)
                    {
                        char    theTypeCString[MAX_TYPE_STRING_LENGTH];

                        theTypeCString[0]   = 0;

                        GetDescription(theTypeCString,
                            GetPointer((UInt32)theIvar.ivar_type, nil));
                        snprintf(&tempComment[tempCommentLength],
                            MAX_COMMENT_LENGTH - tempCommentLength - 1,
                            "(%s)%s", theTypeCString, theSymPtr);
                    }
                    else
                        strncat(tempComment, theSymPtr,
                            MAX_COMMENT_LENGTH - tempCommentLength - 1);
                }

                if (tempComment[0])
                    strncpy(iLineCommentCString, tempComment,
                        MAX_COMMENT_LENGTH - 1);
            }
            else    // absolute address
            {
                UInt8   immOffset = 4;

                if (HAS_DISP8(modRM))
                    immOffset   += 2;

                if (HAS_SIB(modRM))
                    immOffset   += 2;

                sscanf(&inLine->info.code[immOffset], "%08x", &localAddy);
                localAddy   = OSSwapInt32(localAddy);

                // Check for a four char code.
                if (localAddy >= 0x20202020 && localAddy < 0x7f7f7f7f)
                {
                    char*   fcc = (char*)&localAddy;

                    if (fcc[0] >= 0x20 && fcc[0] < 0x7f &&
                        fcc[1] >= 0x20 && fcc[1] < 0x7f &&
                        fcc[2] >= 0x20 && fcc[2] < 0x7f &&
                        fcc[3] >= 0x20 && fcc[3] < 0x7f)
                    {
                        #if __LITTLE_ENDIAN__   // reversed on purpose
                            localAddy   = OSSwapInt32(localAddy);
                        #endif

                        snprintf(iLineCommentCString,
                            7, "'%.4s'", fcc);
                    }
                }
                else    // Check for a single printable 7-bit char.
                if (localAddy >= 0x20 && localAddy < 0x7f)
                    snprintf(iLineCommentCString, 4, "'%c'", localAddy);
            }

            break;
        }

        case 0xcd:  // int
            sscanf(&inLine->info.code[2], "%02hhx", &modRM);

            if (modRM == 0x80)
                CommentForSystemCall();

            break;

        case 0xd9:  // fldsl    r/m32
        case 0xdd:  // fldll    
            sscanf(&inLine->info.code[2], "%02hhx", &modRM);

            if (iRegInfos[REG2(modRM)].classPtr)    // address relative to class
            {
                if (!iRegInfos[REG2(modRM)].isValid)
                    break;

                // Ignore the 1st and 4th addressing modes
                if (MOD(modRM) == MODimm || MOD(modRM) == MODx)
                    break;

                objc_ivar   theIvar         = {0};
                objc_class  swappedClass    =
                    *iRegInfos[REG2(modRM)].classPtr;

                #if __BIG_ENDIAN__
                    swap_objc_class(&swappedClass);
                #endif

                if (!iIsInstanceMethod)
                {
                    if (!GetObjcMetaClassFromClass(
                        &swappedClass, &swappedClass))
                        break;

                    #if __BIG_ENDIAN__
                        swap_objc_class(&swappedClass);
                    #endif
                }

                if (MOD(modRM) == MOD8)
                {
                    UInt8   theSymOffset;

                    sscanf(&inLine->info.code[4], "%02hhx", &theSymOffset);

                    if (!FindIvar(&theIvar, &swappedClass, theSymOffset))
                        break;
                }
                else if (MOD(modRM) == MOD32)
                {
                    UInt32  theSymOffset;

                    sscanf(&inLine->info.code[4], "%08x", &theSymOffset);
                    theSymOffset    = OSSwapInt32(theSymOffset);

                    if (!FindIvar(&theIvar, &swappedClass, theSymOffset))
                        break;
                }

                theSymPtr   = GetPointer(
                    (UInt32)theIvar.ivar_name, nil);

                if (theSymPtr)
                {
                    if (iOpts.variableTypes)
                    {
                        char    theTypeCString[MAX_TYPE_STRING_LENGTH];

                        theTypeCString[0]   = 0;

                        GetDescription(theTypeCString,
                            GetPointer((UInt32)theIvar.ivar_type, nil));
                        snprintf(iLineCommentCString,
                            MAX_COMMENT_LENGTH - 1, "(%s)%s",
                            theTypeCString, theSymPtr);
                    }
                    else
                        snprintf(iLineCommentCString,
                            MAX_COMMENT_LENGTH - 1, "%s",
                            theSymPtr);
                }
            }
            else    // absolute address
            {
                UInt8   immOffset = 4;

                if (HAS_DISP8(modRM))
                    immOffset   += 2;

                if (HAS_SIB(modRM))
                    immOffset   += 2;

                sscanf(&inLine->info.code[immOffset], "%08x", &localAddy);
                localAddy   = OSSwapInt32(localAddy);

                theDummyPtr = GetPointer(localAddy, nil);

                if (!theDummyPtr)
                    break;

                if (LO(opcode) == 0x9)  // fldsl
                {
                    UInt32  theInt32    = *(UInt32*)theDummyPtr;

                    theInt32    = OSSwapLittleToHostInt32(theInt32);

                    // dance around printf's type coersion
                    snprintf(iLineCommentCString,
                        30, "%G", *(float*)&theInt32);
                }
                else if (LO(opcode) == 0xd) // fldll
                {
                    UInt64  theInt64    = *(UInt64*)theDummyPtr;

                    theInt64    = OSSwapLittleToHostInt64(theInt64);

                    // dance around printf's type coersion
                    snprintf(iLineCommentCString,
                        30, "%lG", *(double*)&theInt64);
                }
            }

            break;

        case 0xe8:  // call
        case 0xe9:  // jmp
        {
            // Insert anonymous label if there's not a label yet.
            if (iLineCommentCString[0])
                break;

            sscanf(&inLine->info.code[2], "%08x", &localAddy);
            localAddy   = OSSwapInt32(localAddy);

            UInt32  absoluteAddy    =
                inLine->info.address + 5 + (SInt32)localAddy;

// FIXME: can we use mCurrentFuncInfoIndex here?
            FunctionInfo    searchKey   = {absoluteAddy, NULL, 0, 0};
            FunctionInfo*   funcInfo    = bsearch(&searchKey,
                iFuncInfos, iNumFuncInfos, sizeof(FunctionInfo),
                (COMPARISON_FUNC_TYPE)Function_Info_Compare);

            if (funcInfo && funcInfo->genericFuncNum != 0)
                snprintf(iLineCommentCString,
                    ANON_FUNC_BASE_LENGTH + 11, "%s%d",
                    ANON_FUNC_BASE, funcInfo->genericFuncNum);

            break;
        }

        case 0xf2:  // repne/repnz or movsd, mulsd etc
        case 0xf3:  // rep/repe or movss, mulss etc
        {
            UInt8   byte2;

            sscanf(&inLine->info.code[2], "%02hhx", &byte2);

            if (byte2 != 0x0f)  // movsd/s, divsd/s, addsd/s etc
                break;

            sscanf(&inLine->info.code[6], "%02hhx", &modRM);

            if (iRegInfos[REG2(modRM)].classPtr)    // address relative to self
            {
                if (!iRegInfos[REG2(modRM)].isValid)
                    break;

                // Ignore the 1st and 4th addressing modes
                if (MOD(modRM) == MODimm || MOD(modRM) == MODx)
                    break;

                objc_ivar   theIvar         = {0};
                objc_class  swappedClass    =
                    *iRegInfos[REG2(modRM)].classPtr;

                #if __BIG_ENDIAN__
                    swap_objc_class(&swappedClass);
                #endif

                if (!iIsInstanceMethod)
                {
                    if (!GetObjcMetaClassFromClass(
                        &swappedClass, &swappedClass))
                        break;

                    #if __BIG_ENDIAN__
                        swap_objc_class(&swappedClass);
                    #endif
                }

                if (MOD(modRM) == MOD8)
                {
                    UInt8   theSymOffset;

                    sscanf(&inLine->info.code[8], "%02hhx", &theSymOffset);

                    if (!FindIvar(&theIvar, &swappedClass, theSymOffset))
                        break;
                }
                else if (MOD(modRM) == MOD32)
                {
                    UInt32  theSymOffset;

                    sscanf(&inLine->info.code[8], "%08x", &theSymOffset);
                    theSymOffset    = OSSwapInt32(theSymOffset);

                    if (!FindIvar(&theIvar, &swappedClass, theSymOffset))
                        break;
                }

                theSymPtr   = GetPointer(
                    (UInt32)theIvar.ivar_name, nil);

                if (theSymPtr)
                {
                    if (iOpts.variableTypes)
                    {
                        char    theTypeCString[MAX_TYPE_STRING_LENGTH];

                        theTypeCString[0]   = 0;

                        GetDescription(theTypeCString,
                            GetPointer((UInt32)theIvar.ivar_type, nil));

                        snprintf(iLineCommentCString,
                            MAX_COMMENT_LENGTH - 1, "(%s)%s",
                            theTypeCString, theSymPtr);
                    }
                    else
                        snprintf(iLineCommentCString,
                            MAX_COMMENT_LENGTH - 1, "%s", theSymPtr);
                }
            }
            else    // absolute address
            {
                sscanf(&inLine->info.code[8], "%08x", &localAddy);
                localAddy   = OSSwapInt32(localAddy);

                theDummyPtr = GetPointer(localAddy, nil);

                if (theDummyPtr)
                {
                    if (LO(opcode) == 0x3)
                    {
                        UInt32  theInt32    = *(UInt32*)theDummyPtr;

                        theInt32    = OSSwapLittleToHostInt32(theInt32);
                        snprintf(iLineCommentCString,
                            30, "%G", *(float*)&theInt32);
                    }
                    else if (LO(opcode) == 0x2)
                    {
                        UInt64  theInt64    = *(UInt64*)theDummyPtr;

                        theInt64    = OSSwapLittleToHostInt64(theInt64);
                        snprintf(iLineCommentCString,
                            30, "%lG", *(double*)&theInt64);
                    }
                }
            }

            break;
        }

        default:
            break;
    }   // switch (opcode)

    if (!iLineCommentCString[0])
    {
        UInt8   theType     = PointerType;
        UInt32  theValue;

        theDummyPtr = GetPointer(localAddy, &theType);

        if (theDummyPtr)
        {
            switch (theType)
            {
                case DataGenericType:
                    theValue    = *(UInt32*)theDummyPtr;
                    theValue    = OSSwapLittleToHostInt32(theValue);
                    theDummyPtr = GetPointer(theValue, &theType);

                    switch (theType)
                    {
                        case PointerType:
                            theSymPtr   = theDummyPtr;
                            break;

                        default:
                            theSymPtr   = nil;
                            break;
                    }

                    break;

                case DataConstType:
                    theSymPtr   = nil;

                    break;

                case PStringType:
                case PointerType:
                    theSymPtr   = theDummyPtr;

                    break;

                case CFStringType:
                {
                    cf_string_object    theCFString = 
                        *(cf_string_object*)theDummyPtr;

                    if (theCFString.oc_string.length == 0)
                    {
                        theSymPtr   = nil;
                        break;
                    }

                    theValue    = (UInt32)theCFString.oc_string.chars;
                    theValue    = OSSwapLittleToHostInt32(theValue);
                    theSymPtr   = GetPointer(theValue, nil);

                    break;
                }
                case ImpPtrType:
                case NLSymType:
                {
                    theValue    = *(UInt32*)theDummyPtr;
                    theValue    = OSSwapLittleToHostInt32(theValue);
                    theDummyPtr = GetPointer(theValue, nil);

                    if (!theDummyPtr)
                    {
                        theSymPtr   = nil;
                        break;
                    }

                    theValue    = *(UInt32*)(theDummyPtr + 4);
                    theValue    = OSSwapLittleToHostInt32(theValue);

                    if (theValue != typeid_NSString)
                    {
                        theValue    = *(UInt32*)theDummyPtr;
                        theValue    = OSSwapLittleToHostInt32(theValue);
                        theDummyPtr = GetPointer(theValue, nil);

                        if (!theDummyPtr)
                        {
                            theSymPtr   = nil;
                            break;
                        }
                    }

                    cf_string_object    theCFString = 
                        *(cf_string_object*)theDummyPtr;

                    if (theCFString.oc_string.length == 0)
                    {
                        theSymPtr   = nil;
                        break;
                    }

                    theValue    = (UInt32)theCFString.oc_string.chars;
                    theValue    = OSSwapLittleToHostInt32(theValue);
                    theSymPtr   = GetPointer( theValue, nil);

                    break;
                }

                case OCGenericType:
                case OCStrObjectType:
                case OCClassType:
                case OCModType:
                    GetObjcDescriptionFromObject(
                        &theSymPtr, theDummyPtr, theType);

                    break;

                default:
                    break;
            }
        }

        if (theSymPtr)
        {
            if (theType == PStringType)
                snprintf(iLineCommentCString, 255,
                    "%*s", theSymPtr[0], theSymPtr + 1);
            else
                snprintf(iLineCommentCString,
                    MAX_COMMENT_LENGTH - 1, "%s", theSymPtr);
        }
    }
}

//  commentForSystemCall
// ----------------------------------------------------------------------------
//  System call number is stored in EAX, possible values defined in
//  <sys/syscall.h>. Call numbers are indices into a lookup table of handler
//  routines. Args being passed to the looked-up handler are on the stack.

- (void)commentForSystemCall
{
    if (!iRegInfos[EAX].isValid ||
         iRegInfos[EAX].value > SYS_MAXSYSCALL)
    {
        snprintf(iLineCommentCString, 11, "syscall(?)");
        return;
    }

    BOOL        isIndirect  = (iRegInfos[EAX].value == SYS_syscall);
    UInt32      syscallNum;
    UInt32      syscallArgIndex = (isIndirect) ? 1 : 0;
    const char* theSysString    = nil;

    if (isIndirect && iStack[0].isValid &&
        iStack[0].value <= SYS_MAXSYSCALL)
        syscallNum  = iStack[0].value;
    else
        syscallNum  = iRegInfos[EAX].value;

    theSysString    = gSysCalls[syscallNum];

    if (!theSysString)
        return;

    char    theTempComment[50];

    theTempComment[0]   = 0;

    strncpy(theTempComment, theSysString, strlen(theSysString) + 1);

    // Handle various system calls.
    switch(syscallNum)
    {
        case SYS_ptrace:
            if (iStack[syscallArgIndex].isValid &&
                iStack[syscallArgIndex].value == PT_DENY_ATTACH)
                snprintf(iLineCommentCString, 40, "%s(%s)",
                    theTempComment, "PT_DENY_ATTACH");
            else
                strncpy(iLineCommentCString, theTempComment,
                    strlen(theTempComment) + 1);

            break;

        default:
            strncpy(iLineCommentCString, theTempComment,
                strlen(theTempComment) + 1);

            break;
    }
}

//  selectorForMsgSend:fromLine:
// ----------------------------------------------------------------------------

- (char*)selectorForMsgSend: (char*)outComment
                   fromLine: (Line*)inLine
{
    char*   selString   = nil;

    UInt8   opcode;

    sscanf(inLine->info.code, "%02hhx", &opcode);

    // Bail if this is not an eligible jump.
    if (opcode != 0xe8  &&  // calll
        opcode != 0xe9)     // jmpl
        return nil;

    // Bail if this is not an objc_msgSend variant.
    // FIXME: this is redundant now.
    if (memcmp(outComment, "_objc_msgSend", 13))
        return nil;

    // Store the variant type locally to reduce string comparisons.
    UInt32  sendType    = SendTypeFromMsgSend(outComment);
    UInt32  receiverAddy;
    UInt32  selectorAddy;

    // Make sure we know what the selector is.
    if (sendType == sendSuper_stret || sendType == send_stret)
    {
        if (iStack[2].isValid)
        {
            selectorAddy    = iStack[2].value;
            receiverAddy    = (iStack[1].isValid) ?
                iStack[1].value : 0;
        }
        else
            return nil;
    }
    else
    {
        if (iStack[1].isValid)
        {
            selectorAddy    = iStack[1].value;
            receiverAddy    = (iStack[0].isValid) ?
                iStack[0].value : 0;
        }
        else
            return nil;
    }

    // sanity check
    if (!selectorAddy)
        return nil;

    // Get at the selector.
    UInt8   selType = PointerType;
    char*   selPtr  = GetPointer(selectorAddy, &selType);

    switch (selType)
    {
        case PointerType:
            selString   = selPtr;

            break;

        case OCGenericType:
            if (selPtr)
            {
                UInt32  selPtrValue = *(UInt32*)selPtr;

                selPtrValue = OSSwapLittleToHostInt32(selPtrValue);
                selString   = GetPointer(selPtrValue, nil);
            }

            break;

        default:
            fprintf(stderr, "otx: [X86Processor selectorForMsgSend:fromLine:]: "
                "unsupported selector type: %d at address: 0x%x\n",
                selType, inLine->info.address);

            break;
    }

    return selString;
}

//  commentForMsgSend:fromLine:
// ----------------------------------------------------------------------------

- (void)commentForMsgSend: (char*)ioComment
                 fromLine: (Line*)inLine
{
    char    tempComment[MAX_COMMENT_LENGTH];

    tempComment[0]  = 0;

    if (!strncmp(ioComment, "_objc_msgSend", 13))
    {
        char*   selString   = SelectorForMsgSend(ioComment, inLine);

        // Bail if we couldn't find the selector.
        if (!selString)
            return;

        UInt8   sendType    = SendTypeFromMsgSend(ioComment);

        // Get the address of the class name string, if this a class method.
        UInt32  classNameAddy   = 0;

        // If *.classPtr is non-nil, it's not a name string.
        if (sendType == sendSuper_stret || sendType == send_stret)
        {
            if (iStack[1].isValid && !iStack[1].classPtr)
                classNameAddy   = iStack[1].value;
        }
        else
        {
            if (iStack[0].isValid && !iStack[0].classPtr)
                classNameAddy   = iStack[0].value;
        }

        char*   className           = nil;
        char*   returnTypeString    =
            (sendType == sendSuper_stret || sendType == send_stret) ?
            "(struct)" : (sendType == send_fpret) ? "(double)" : "";

        if (classNameAddy)
        {
            // Get at the class name
            UInt8   classNameType   = PointerType;
            char*   classNamePtr    = GetPointer(classNameAddy, &classNameType);

            switch (classNameType)
            {
                // Receiver can be a static string or pointer in these sections, but we
                // only want to display class names as receivers.
                case DataGenericType:
                case DataConstType:
                case CFStringType:
                case ImpPtrType:
                case OCStrObjectType:
                    break;

                case PointerType:
                    className   = classNamePtr;
                    break;

                case OCGenericType:
                    if (classNamePtr)
                    {
                        UInt32  namePtrValue    = *(UInt32*)classNamePtr;

                        namePtrValue    = OSSwapLittleToHostInt32(namePtrValue);
                        className   = GetPointer(namePtrValue, nil);
                    }

                    break;

                case OCClassType:
                    if (classNamePtr)
                        GetObjcDescriptionFromObject(
                            &className, classNamePtr, OCClassType);

                    break;

                default:
                    fprintf(stderr, "otx: [X86Processor commentForMsgSend]: "
                        "unsupported class name type: %d at address: 0x%x\n",
                        classNameType, inLine->info.address);

                    break;
            }
        }

        if (className)
        {
            snprintf(ioComment, MAX_COMMENT_LENGTH - 1,
                (sendType == sendSuper || sendType == sendSuper_stret) ?
                "+%s[[%s super] %s]" : "+%s[%s %s]",
                returnTypeString, className, selString);
        }
        else
        {
            char*   formatString    = nil;

            switch (sendType)
            {
                case send:
                case send_fpret:
                case send_variadic:
                    formatString    = "-%s[(%%esp,1) %s]";
                    break;

                case sendSuper:
                    formatString    = "-%s[[(%%esp,1) super] %s]";
                    break;

                case send_stret:
                    formatString    = "-%s[0x04(%%esp,1) %s]";
                    break;

                case sendSuper_stret:
                    formatString    = "-%s[[0x04(%%esp,1) super] %s]";
                    break;

                default:
                    break;
            }

            if (formatString)
                snprintf(ioComment, MAX_COMMENT_LENGTH - 1, formatString,
                    returnTypeString, selString);
        }
    }
    else if (!strncmp(ioComment, "_objc_assign_ivar", 17))
    {
        if (iCurrentClass && iStack[2].isValid)
        {
            char*       theSymPtr       = nil;
            objc_ivar   theIvar         = {0};
            objc_class  swappedClass    = *iCurrentClass;

            #if __BIG_ENDIAN__
                swap_objc_class(&swappedClass);
            #endif

            if (!iIsInstanceMethod)
            {
                if (!GetObjcMetaClassFromClass(
                    &swappedClass, &swappedClass))
                    return;

                #if __BIG_ENDIAN__
                    swap_objc_class(&swappedClass);
                #endif
            }

            if (!FindIvar(&theIvar, &swappedClass, iStack[2].value))
                return;

            theSymPtr   = GetPointer((UInt32)theIvar.ivar_name, nil);

            if (!theSymPtr)
                return;

            if (iOpts.variableTypes)
            {
                char    theTypeCString[MAX_TYPE_STRING_LENGTH];

                theTypeCString[0]   = 0;

                GetDescription(theTypeCString,
                    GetPointer((UInt32)theIvar.ivar_type, nil));
                snprintf(tempComment,
                    MAX_COMMENT_LENGTH - 1, " (%s)%s",
                    theTypeCString, theSymPtr);
            }
            else
                snprintf(tempComment,
                    MAX_COMMENT_LENGTH - 1, " %s", theSymPtr);

            strncat(ioComment, tempComment, strlen(tempComment));
        }
    }
}

//  chooseLine:
// ----------------------------------------------------------------------------

- (void)chooseLine: (Line**)ioLine
{
    if (!(*ioLine) || !(*ioLine)->info.isCode ||
        !(*ioLine)->alt || !(*ioLine)->alt->chars)
        return;

    UInt8   theCode;

    sscanf((*ioLine)->info.code, "%02hhx", &theCode);

    if (theCode == 0xe8 || theCode == 0xff || theCode == 0x9a)
    {
        Line*   theNewLine  = malloc(sizeof(Line));

        memcpy(theNewLine, (*ioLine)->alt, sizeof(Line));
        theNewLine->chars   = malloc(theNewLine->length + 1);
        strncpy(theNewLine->chars, (*ioLine)->alt->chars,
            theNewLine->length + 1);

        // Swap in the verbose line and free the previous verbose lines.
        DeleteLinesBefore((*ioLine)->alt, &iVerboseLineListHead);
        ReplaceLine(*ioLine, theNewLine, &iPlainLineListHead);
        *ioLine = theNewLine;
    }
}

//  postProcessCodeLine:
// ----------------------------------------------------------------------------

- (void)postProcessCodeLine: (Line**)ioLine
{
    if ((*ioLine)->info.code[0] != 'e'  ||  // calll
        (*ioLine)->info.code[1] != '8'  ||
        !(*ioLine)->next)
        return;

    // Check for thunks.
    char*   theSubstring    =
        strstr(iLineOperandsCString, "i686.get_pc_thunk.");

    if (theSubstring)   // otool knew this was a thunk call
    {
        BOOL applyThunk = YES;

        if (!strncmp(&theSubstring[18], "ax", 2))
            iCurrentThunk = EAX;
        else if (!strncmp(&theSubstring[18], "bx", 2))
            iCurrentThunk = EBX;
        else if (!strncmp(&theSubstring[18], "cx", 2))
            iCurrentThunk = ECX;
        else if (!strncmp(&theSubstring[18], "dx", 2))
            iCurrentThunk = EDX;
        else
            applyThunk = NO;

        if (applyThunk)
        {
            iRegInfos[iCurrentThunk].value      =
                (*ioLine)->next->info.address;
            iRegInfos[iCurrentThunk].isValid    = YES;
        }
    }
    else if (iThunks)   // otool didn't spot it, maybe we did earlier...
    {
        UInt32  i, target;
        BOOL    found   = NO;

        for (i = 0; i < iNumThunks && !found; i++)
        {
            target  = strtoul(iLineOperandsCString, nil, 16);

            if (target == iThunks[i].address)
            {
                found           = YES;
                iCurrentThunk   = iThunks[i].reg;

                iRegInfos[iCurrentThunk].value      =
                    (*ioLine)->next->info.address;
                iRegInfos[iCurrentThunk].isValid    = YES;

                return;
            }
        }
    }
}

#pragma mark -
//  resetRegisters:
// ----------------------------------------------------------------------------

- (void)resetRegisters: (Line*)inLine
{
    if (!inLine)
    {
        fprintf(stderr, "otx: [X86Processor resetRegisters]: "
            "tried to reset with nil ioLine\n");
        return;
    }

    GetObjcClassPtrFromMethod(&iCurrentClass, inLine->info.address);
    GetObjcCatPtrFromMethod(&iCurrentCat, inLine->info.address);

    iCurrentThunk   = NO_REG;
    memset(iRegInfos, 0, sizeof(GPRegisterInfo) * 8);

    // If we didn't get the class from the method, try to get it from the
    // category.
    if (!iCurrentClass && iCurrentCat)
    {
        objc_category   swappedCat  = *iCurrentCat;

        #if __BIG_ENDIAN__
            swap_objc_category(&swappedCat);
        #endif

        GetObjcClassPtrFromName(&iCurrentClass,
            GetPointer((UInt32)swappedCat.class_name, nil));
    }

    // Try to find out whether this is a class or instance method.
    MethodInfo* thisMethod  = nil;

    if (GetObjcMethodFromAddress(&thisMethod, inLine->info.address))
        iIsInstanceMethod   = thisMethod->inst;

    if (iLocalSelves)
    {
        free(iLocalSelves);
        iLocalSelves    = nil;
        iNumLocalSelves = 0;
    }

    if (iLocalVars)
    {
        free(iLocalVars);
        iLocalVars      = nil;
        iNumLocalVars   = 0;
    }

    iCurrentFuncInfoIndex++;

    if (iCurrentFuncInfoIndex >= iNumFuncInfos)
        iCurrentFuncInfoIndex   = -1;
}

//  updateRegisters:
// ----------------------------------------------------------------------------

- (void)updateRegisters: (Line*)inLine;
{
    UInt8   opcode;
    UInt8   opcode2;
    UInt8   modRM;

    sscanf(inLine->info.code, "%02hhx", &opcode);
    sscanf(&inLine->info.code[2], "%02hhx", &opcode2);

    switch (opcode)
    {
        // pop stack into thunk registers.
        case 0x58:  // eax
        case 0x59:  // ecx
        case 0x5a:  // edx
        case 0x5b:  // ebx
            iRegInfos[REG2(opcode)] = (GPRegisterInfo){0};

            if (inLine->prev &&
                (inLine->prev->info.code[0] == 'e') &&
                (inLine->prev->info.code[1] == '8') &&
                (strtoul(&inLine->prev->info.code[2], nil, 16) == 0))
            {
                iRegInfos[REG2(opcode)].value   = inLine->info.address;
                iRegInfos[REG2(opcode)].isValid = YES;
                iCurrentThunk                   = REG2(opcode);
            }

            break;

        // pop stack into non-thunk registers. Wipe em.
        case 0x5c:  // esp
        case 0x5d:  // ebp
        case 0x5e:  // esi
        case 0x5f:  // edi
            iRegInfos[REG2(opcode)] = (GPRegisterInfo){0};

            break;

        // immediate group 1
        // add, or, adc, sbb, and, sub, xor, cmp
        case 0x83:  // EXTS(imm8),r32
        {
            sscanf(&inLine->info.code[2], "%02hhx", &modRM);

            if (!iRegInfos[REG1(modRM)].isValid)
                break;

            UInt8   imm;

            sscanf(&inLine->info.code[4], "%02hhx", &imm);

            switch (OPEXT(modRM))
            {
                case 0: // add
                    iRegInfos[REG1(modRM)].value    += (SInt32)imm;
                    iRegInfos[REG1(modRM)].classPtr = nil;
                    iRegInfos[REG1(modRM)].catPtr   = nil;

                    break;

                case 1: // or
                    iRegInfos[REG1(modRM)].value    |= (SInt32)imm;
                    iRegInfos[REG1(modRM)].classPtr = nil;
                    iRegInfos[REG1(modRM)].catPtr   = nil;

                    break;

                case 4: // and
                    iRegInfos[REG1(modRM)].value    &= (SInt32)imm;
                    iRegInfos[REG1(modRM)].classPtr = nil;
                    iRegInfos[REG1(modRM)].catPtr   = nil;

                    break;

                case 5: // sub
                    iRegInfos[REG1(modRM)].value    -= (SInt32)imm;
                    iRegInfos[REG1(modRM)].classPtr = nil;
                    iRegInfos[REG1(modRM)].catPtr   = nil;

                    break;

                case 6: // xor
                    iRegInfos[REG1(modRM)].value    ^= (SInt32)imm;
                    iRegInfos[REG1(modRM)].classPtr = nil;
                    iRegInfos[REG1(modRM)].catPtr   = nil;

                    break;

                default:
                    break;
            }   // switch (OPEXT(modRM))

            break;
        }

        case 0x89:  // mov reg to r/m
        {
            sscanf(&inLine->info.code[2], "%02hhx", &modRM);

            if (MOD(modRM) == MODx) // reg to reg
            {
                if (!iRegInfos[REG1(modRM)].isValid)
                    iRegInfos[REG2(modRM)]  = (GPRegisterInfo){0};
                else
                    memcpy(&iRegInfos[REG2(modRM)], &iRegInfos[REG1(modRM)],
                        sizeof(GPRegisterInfo));

                break;
            }

            if ((REG2(modRM) != EBP && !HAS_SIB(modRM)))
                break;

            SInt8   offset  = 0;

            if (HAS_SIB(modRM)) // pushing an arg onto stack
            {
                if (HAS_DISP8(modRM))
                    sscanf(&inLine->info.code[6], "%02hhx", &offset);

                if (offset >= 0)
                {
                    if (offset / 4 > MAX_STACK_SIZE - 1)
                    {
                        fprintf(stderr, "otx: out of stack bounds: "
                            "stack size needs to be %d\n", (offset / 4) + 1);
                        break;
                    }

                    // Convert offset to array index.
                    offset /= 4;

                    if (iRegInfos[REG1(modRM)].isValid)
                        iStack[offset]  = iRegInfos[REG1(modRM)];
                    else
                        iStack[offset]  = (GPRegisterInfo){0};
                }
            }
            else    // Copying from a register to a local var.
            {
                if (iRegInfos[REG1(modRM)].classPtr && MOD(modRM) == MOD8)
                {
                    sscanf(&inLine->info.code[4], "%02hhx", &offset);

                    iNumLocalSelves++;
                    iLocalSelves = realloc(iLocalSelves,
                        iNumLocalSelves * sizeof(VarInfo));
                    iLocalSelves[iNumLocalSelves - 1]   = (VarInfo)
                        {iRegInfos[REG1(modRM)], offset};
                }
                else if (iRegInfos[REG1(modRM)].isValid && MOD(modRM) == MOD32)
                {
                    SInt32  varOffset;

                    sscanf(&inLine->info.code[4], "%08x", &varOffset);
                    varOffset   = OSSwapInt32(varOffset);

                    iNumLocalVars++;
                    iLocalVars  = realloc(iLocalVars,
                        iNumLocalVars * sizeof(VarInfo));
                    iLocalVars[iNumLocalVars - 1]   = (VarInfo)
                        {iRegInfos[REG1(modRM)], varOffset};
                }
            }

            break;
        }

        case 0x8b:  // mov mem to reg
        case 0x8d:  // lea mem to reg
            sscanf(&inLine->info.code[2], "%02hhx", &modRM);

            iRegInfos[REG1(modRM)]  = (GPRegisterInfo){0};

            if (MOD(modRM) == MODimm)
            {
                UInt32 offset;

                sscanf(&inLine->info.code[4], "%08x", &offset);
                offset = OSSwapInt32(offset);

                iRegInfos[REG1(modRM)] = (GPRegisterInfo){0};
                iRegInfos[REG1(modRM)].value = offset;
                iRegInfos[REG1(modRM)].isValid = YES;
                // FIXME should we update .classPtr here?
            }
            else if (MOD(modRM) == MOD8)
            {
                SInt8 offset;

                sscanf(&inLine->info.code[4], "%02hhx", &offset);

                if (REG2(modRM) == EBP && offset == 0x8)
                {   // Copying self from 1st arg to a register.
                    iRegInfos[REG1(modRM)].classPtr = iCurrentClass;
                    iRegInfos[REG1(modRM)].catPtr   = iCurrentCat;
                    iRegInfos[REG1(modRM)].isValid  = YES;
                }
                else
                {   // Check for copied self pointer.
                    if (iLocalSelves        &&
                        REG2(modRM) == EBP  &&
                        offset < 0)
                    {
                        UInt32  i;

                        // Zero the destination regardless.
                        iRegInfos[REG1(modRM)]  = (GPRegisterInfo){0};

                        // If we're accessing a local var copy of self,
                        // copy that info back to the reg in question.
                        for (i = 0; i < iNumLocalSelves; i++)
                        {
                            if (iLocalSelves[i].offset != offset)
                                continue;

                            iRegInfos[REG1(modRM)]  = iLocalSelves[i].regInfo;

                            break;
                        }
                    }
                }
            }
            else if (REG2(modRM) == EBP && MOD(modRM) == MOD32)
            {
                if (iLocalVars)
                {
                    SInt32  offset;

                    sscanf(&inLine->info.code[4], "%08x", &offset);
                    offset  = OSSwapInt32(offset);

                    if (offset < 0)
                    {
                        UInt32  i;

                        for (i = 0; i < iNumLocalVars; i++)
                        {
                            if (iLocalVars[i].offset != offset)
                                continue;

                            iRegInfos[REG1(modRM)]  = iLocalVars[i].regInfo;

                            break;
                        }
                    }
                }
            }
            else if (HAS_ABS_DISP32(modRM))
            {
                sscanf(&inLine->info.code[4], "%08x",
                    &iRegInfos[REG1(modRM)].value);
                iRegInfos[REG1(modRM)].value    =
                    OSSwapInt32(iRegInfos[REG1(modRM)].value);
                iRegInfos[REG1(modRM)].isValid  = YES;
            }
            else if (HAS_REL_DISP32(modRM))
            {
                if (!iRegInfos[REG2(modRM)].isValid)
                    break;

                sscanf(&inLine->info.code[4], "%08x",
                    &iRegInfos[REG1(modRM)].value);
                iRegInfos[REG1(modRM)].value    =
                    OSSwapInt32(iRegInfos[REG1(modRM)].value);
                iRegInfos[REG1(modRM)].value    += iRegInfos[REG2(modRM)].value;
                iRegInfos[REG1(modRM)].isValid  = YES;
            }

            break;

        case 0xb0:  // movb imm8,%al
        case 0xb1:  // movb imm8,%cl
        case 0xb2:  // movb imm8,%dl
        case 0xb3:  // movb imm8,%bl
        case 0xb4:  // movb imm8,%ah
        case 0xb5:  // movb imm8,%ch
        case 0xb6:  // movb imm8,%dh
        case 0xb7:  // movb imm8,%bh
        {
            UInt8   imm;

            iRegInfos[REG2(opcode)] = (GPRegisterInfo){0};

            sscanf(&inLine->info.code[2], "%02hhx", &imm);
            iRegInfos[REG2(opcode)].value = imm;
            iRegInfos[REG2(opcode)].isValid = YES;

            break;
        }

        case 0xa1:  // movl moffs32,%eax
            iRegInfos[EAX]  = (GPRegisterInfo){0};

            sscanf(&inLine->info.code[2], "%08x", &iRegInfos[EAX].value);
            iRegInfos[EAX].value = OSSwapInt32(iRegInfos[EAX].value);
            iRegInfos[EAX].isValid = YES;

            break;

        case 0xb8:  // movl imm32,%eax
        case 0xb9:  // movl imm32,%ecx
        case 0xba:  // movl imm32,%edx
        case 0xbb:  // movl imm32,%ebx
        case 0xbc:  // movl imm32,%esp
        case 0xbd:  // movl imm32,%ebp
        case 0xbe:  // movl imm32,%esi
        case 0xbf:  // movl imm32,%edi
            iRegInfos[REG2(opcode)] = (GPRegisterInfo){0};

            sscanf(&inLine->info.code[2], "%08x",
                &iRegInfos[REG2(opcode)].value);
            iRegInfos[REG2(opcode)].value   =
                OSSwapInt32(iRegInfos[REG2(opcode)].value);
            iRegInfos[REG2(opcode)].isValid = YES;

            break;

        case 0xc7:  // movl imm32,r/m32
        {
            sscanf(&inLine->info.code[2], "%02hhx", &modRM);

            if (!HAS_SIB(modRM))
                break;

            SInt8   offset  = 0;
            SInt32  value   = 0;

            if (HAS_DISP8(modRM))
            {
                sscanf(&inLine->info.code[6], "%02hhx", &offset);
                sscanf(&inLine->info.code[8], "%08x", &value);
                value   = OSSwapInt32(value);
            }

            if (offset >= 0)
            {
                if (offset / 4 > MAX_STACK_SIZE - 1)
                {
                    fprintf(stderr, "otx: out of stack bounds: "
                        "stack size needs to be %d\n", (offset / 4) + 1);
                    break;
                }

                // Convert offset to array index.
                offset /= 4;

                iStack[offset]          = (GPRegisterInfo){0};
                iStack[offset].value    = value;
                iStack[offset].isValid  = YES;
            }

            break;
        }

        case 0xe8:  // calll
                memset(iStack, 0, sizeof(GPRegisterInfo) * MAX_STACK_SIZE);
                iRegInfos[EAX]  = (GPRegisterInfo){0};

            break;

        default:
            break;
    }   // switch (opcode)
}

//  restoreRegisters:
// ----------------------------------------------------------------------------

- (BOOL)restoreRegisters: (Line*)inLine
{
    if (!inLine)
    {
        fprintf(stderr, "otx: [X86Processor restoreRegisters]: "
            "tried to restore with nil inLine\n");
        return NO;
    }

    BOOL needNewLine = NO;

    if (iCurrentFuncInfoIndex < 0)
        return NO;

    // Search current FunctionInfo for blocks that start at this address.
    FunctionInfo*   funcInfo    =
        &iFuncInfos[iCurrentFuncInfoIndex];

    if (!funcInfo->blocks)
        return NO;

    UInt32  i;

    for (i = 0; i < funcInfo->numBlocks; i++)
    {
        if (funcInfo->blocks[i].beginAddress != inLine->info.address)
            continue;

        // Update machine state.
        MachineState    machState   = funcInfo->blocks[i].state;

        memcpy(iRegInfos, machState.regInfos,
            sizeof(GPRegisterInfo) * 8);

        if (machState.localSelves)
        {
            if (iLocalSelves)
                free(iLocalSelves);

            iNumLocalSelves = machState.numLocalSelves;
            iLocalSelves    = malloc(
                sizeof(VarInfo) * machState.numLocalSelves);
            memcpy(iLocalSelves, machState.localSelves,
                sizeof(VarInfo) * machState.numLocalSelves);
        }

        if (machState.localVars)
        {
            if (iLocalVars)
                free(iLocalVars);

            iNumLocalVars   = machState.numLocalVars;
            iLocalVars      = malloc(
                sizeof(VarInfo) * iNumLocalVars);
            memcpy(iLocalVars, machState.localVars,
                sizeof(VarInfo) * iNumLocalVars);
        }

        // Optionally add a blank line before this block.
        if (iOpts.separateLogicalBlocks && inLine->chars[0] != '\n' &&
            !inLine->info.isFunction)
            needNewLine = YES;

        break;
    }   // for (i = 0...)

    return needNewLine;
}

//  lineIsFunction:
// ----------------------------------------------------------------------------

- (BOOL)lineIsFunction: (Line*)inLine
{
    if (!inLine)
        return NO;

    UInt32  theAddy = inLine->info.address;

    if (theAddy == iAddrDyldStubBindingHelper   ||
        theAddy == iAddrDyldFuncLookupPointer)
        return YES;

    MethodInfo* theDummyInfo    = nil;

    // In Obj-C apps, the majority of funcs will have Obj-C symbols, so check
    // those first.
    if (FindClassMethodByAddress(&theDummyInfo, theAddy))
        return YES;

    if (FindCatMethodByAddress(&theDummyInfo, theAddy))
        return YES;

    // If it's not an Obj-C method, maybe there's an nlist.
    if (FindSymbolByAddress(theAddy))
        return YES;

    // If otool gave us a function name, but it came from a dynamic symbol...
    if (inLine->prev && !inLine->prev->info.isCode)
        return YES;

    // Check for saved thunks.
    if (iThunks)
    {
        UInt32  i;

        for (i = 0; i < iNumThunks; i++)
        {
            if (iThunks[i].address == theAddy)
                return YES;
        }
    }

    // Obvious avenues expended, brute force check now.
    BOOL    isFunction  = NO;
    UInt8   opcode;
    Line*   thePrevLine = inLine->prev;

    sscanf(inLine->info.code, "%02hhx", &opcode);

    if (opcode == 0x55) // pushl %ebp
    {
        // Assume it's a func, unless it's preceded by nops and a symbol.
        isFunction  = YES;

        BOOL foundNops = NO;

        while (thePrevLine)
        {
            if (!thePrevLine->info.isCode)
            {
                if (foundNops)
                {
                    isFunction  = NO;
                    break;
                }
                else
                    break;
            }

            sscanf(thePrevLine->info.code, "%02hhx", &opcode);

            if (opcode == 0x90)
                foundNops   = YES;
            else
                break;

            thePrevLine = thePrevLine->prev;
        }
    }
    else
    {   // Check for the first instruction in this section.
        while (thePrevLine)
        {
            if (thePrevLine->info.isCode)
                break;
            else
                thePrevLine = thePrevLine->prev;
        }

        if (!thePrevLine)
            isFunction = YES;
    }

    return isFunction;
}

//  codeIsBlockJump:
// ----------------------------------------------------------------------------

- (BOOL)codeIsBlockJump: (char*)inCode
{
    UInt8   opcode, opcode2;

    sscanf(inCode, "%02hhx", &opcode);
    sscanf(&inCode[2], "%02hhx", &opcode2);

    return IS_JUMP(opcode, opcode2);
}

//  gatherFuncInfos
// ----------------------------------------------------------------------------

- (void)gatherFuncInfos
{
    Line*           theLine     = iPlainLineListHead;
    UInt8           opcode, opcode2;
    UInt32          progCounter = 0;

    // Loop thru lines.
    while (theLine)
    {
        if (!(progCounter % (PROGRESS_FREQ * 5)))
        {
            if (gCancel == YES)
                return;

            [NSThread sleepForTimeInterval: 0.0];
        }

        if (!theLine->info.isCode)
        {
            theLine = theLine->next;
            continue;
        }

        sscanf(theLine->info.code, "%02hhx", &opcode);
        sscanf(&theLine->info.code[2], "%02hhx", &opcode2);

        if (theLine->info.isFunction)
        {
            iCurrentFuncPtr = theLine->info.address;
            ResetRegisters(theLine);
        }
        else
        {
            RestoreRegisters(theLine);
            UpdateRegisters(theLine);

            ThunkInfo   theInfo;

            if ([self getThunkInfo: &theInfo forLine: theLine])
            {
                iRegInfos[theInfo.reg].value    = theLine->next->info.address;
                iRegInfos[theInfo.reg].isValid  = YES;
                iCurrentThunk                   = theInfo.reg;
            }
        }

        // Check if we need to save the machine state.
        if (IS_JUMP(opcode, opcode2) && iCurrentFuncInfoIndex >= 0)
        {
            UInt32  jumpTarget;
            BOOL    validTarget = NO;

            // Retrieve the jump target.
            if ((opcode >= 0x71 && opcode <= 0x7f) ||
                opcode == 0xe3 || opcode == 0xeb)
            {
                // No need for sscanf here- opcode2 is already the unsigned
                // second byte, which in this case is the signed offset that
                // we want.
                jumpTarget  = theLine->info.address + 2 + (SInt8)opcode2;
                validTarget = YES;
            }
            else if (opcode == 0xe9 ||
                (opcode == 0x0f && opcode2 >= 0x81 && opcode2 <= 0x8f))
            {
                SInt32  rel32;

                sscanf(&theLine->info.code[2], "%08x", &rel32);
                rel32       = OSSwapInt32(rel32);
                jumpTarget  = theLine->info.address + 5 + rel32;

                validTarget = YES;
            }

            if (!validTarget)
            {
                theLine = theLine->next;
                continue;
            }

            // Retrieve current FunctionInfo.
            FunctionInfo*   funcInfo    =
                &iFuncInfos[iCurrentFuncInfoIndex];
#ifdef REUSE_BLOCKS
            // 'currentBlock' will point to either an existing block which
            // we will update, or a newly allocated block.
            BlockInfo*  currentBlock    = nil;
            Line*       endLine         = NULL;
            BOOL        isEpilog        = NO;
            UInt32      i;

            if (funcInfo->blocks)
            {   // Blocks exist, find 1st one matching this address.
                // This is an exhaustive search, but the speed hit should
                // only be an issue with extremely long functions.
                for (i = 0; i < funcInfo->numBlocks; i++)
                {
                    if (funcInfo->blocks[i].beginAddress == jumpTarget)
                    {
                        currentBlock = &funcInfo->blocks[i];
                        break;
                    }
                }

                if (currentBlock)
                {   // Determine if the target block is an epilog.
                    if (currentBlock->endLine == NULL &&
                        iOpts.returnStatements)
                    {
                        // Find the first line of the target block.
                        Line    searchKey = {NULL, 0, NULL, NULL, NULL, {jumpTarget, {0}, YES, NO}};
                        Line*   searchKeyPtr = &searchKey;
                        Line**  beginLine = bsearch(&searchKeyPtr, iLineArray, iNumCodeLines, sizeof(Line*),
                            (COMPARISON_FUNC_TYPE)Line_Address_Compare);

                        if (beginLine != NULL)
                        {
                            // Walk through the block. It's an epilog if it ends
                            // with 'ret' and contains no 'call's.
                            Line*   nextLine    = *beginLine;
                            BOOL    canBeEpliog = YES;
                            UInt8   tempOpcode = 0;
                            UInt8   tempOpcode2 = 0;

                            while (nextLine)
                            {
                                if (sscanf(nextLine->info.code, "%02hhx", &tempOpcode) != 1)
                                    break;

                                sscanf(&nextLine->info.code[2], "%02hhx", &tempOpcode2);

                                if (IS_CALL(tempOpcode))
                                    canBeEpliog = NO;

                                if (IS_JUMP(tempOpcode, tempOpcode2))
                                {
                                    endLine = nextLine;

                                    if (canBeEpliog && IS_RET(tempOpcode))
                                        isEpilog = YES;

                                    break;
                                }

                                nextLine = nextLine->next;
                            }
                        }

//                      currentBlock->endLine   = endLine;
                    }
                }
                else
                {   // No matching blocks found, so allocate a new one.
                    funcInfo->numBlocks++;
                    funcInfo->blocks = realloc(funcInfo->blocks,
                        sizeof(BlockInfo) * funcInfo->numBlocks);
                    currentBlock =
                        &funcInfo->blocks[funcInfo->numBlocks - 1];
                    *currentBlock = (BlockInfo){0};
                }
            }
            else
            {   // No existing blocks, allocate one.
                funcInfo->numBlocks++;
                funcInfo->blocks    = calloc(1, sizeof(BlockInfo));
                currentBlock        = funcInfo->blocks;
            }

            // sanity check
            if (!currentBlock)
            {
                fprintf(stderr, "otx: [X86Processor gatherFuncInfos] "
                    "currentBlock is nil. Flame the dev.\n");
                return;
            }

            // Create a new MachineState.
            GPRegisterInfo* savedRegs   = malloc(
                sizeof(GPRegisterInfo) * 8);

            memcpy(savedRegs, iRegInfos, sizeof(GPRegisterInfo) * 8);

            VarInfo*    savedSelves = nil;

            if (iLocalSelves)
            {
                savedSelves = malloc(
                    sizeof(VarInfo) * iNumLocalSelves);
                memcpy(savedSelves, iLocalSelves,
                    sizeof(VarInfo) * iNumLocalSelves);
            }

            VarInfo*    savedVars   = nil;

            if (iLocalVars)
            {
                savedVars   = malloc(
                    sizeof(VarInfo) * iNumLocalVars);
                memcpy(savedVars, iLocalVars,
                    sizeof(VarInfo) * iNumLocalVars);
            }

            MachineState    machState   =
                {savedRegs, savedSelves, iNumLocalSelves,
                    savedVars, iNumLocalVars};

            // Store the new BlockInfo.
            BlockInfo   blockInfo   =
                {jumpTarget, endLine, isEpilog, machState};

            memcpy(currentBlock, &blockInfo, sizeof(BlockInfo));
#else
    // At this point, the x86 logic departs from the PPC logic. We seem
    // to get better results by not reusing blocks.

            // Allocate another BlockInfo.
            funcInfo->numBlocks++;
            funcInfo->blocks    = realloc(funcInfo->blocks,
                sizeof(BlockInfo) * funcInfo->numBlocks);
            // Create a new MachineState.
            GPRegisterInfo* savedRegs   = malloc(
                sizeof(GPRegisterInfo) * 8);

            memcpy(savedRegs, mRegInfos, sizeof(GPRegisterInfo) * 8);

            VarInfo*    savedSelves = nil;

            if (mLocalSelves)
            {
                savedSelves = malloc(
                    sizeof(VarInfo) * mNumLocalSelves);
                memcpy(savedSelves, mLocalSelves,
                    sizeof(VarInfo) * mNumLocalSelves);
            }

            VarInfo*    savedVars   = nil;

            if (mLocalVars)
            {
                savedVars   = malloc(
                    sizeof(VarInfo) * mNumLocalVars);
                memcpy(savedVars, mLocalVars,
                    sizeof(VarInfo) * mNumLocalVars);
            }

            MachineState    machState   =
                {savedRegs, savedSelves, mNumLocalSelves
                    savedVars, mNumLocalVars};

            // Create and store a new BlockInfo.
            funcInfo->blocks[funcInfo->numBlocks - 1]   =
                (BlockInfo){jumpTarget, machState};
#endif

        }

        theLine = theLine->next;
    }

    iCurrentFuncInfoIndex   = -1;
}

#pragma mark -
#pragma mark Deobfuscator protocol
//  verifyNops:numFound:
// ----------------------------------------------------------------------------

- (BOOL)verifyNops: (unsigned char***)outList
          numFound: (UInt32*)outFound
{
    if (![self loadMachHeader])
    {
        fprintf(stderr, "otx: failed to load mach header\n");
        return NO;
    }

    [self loadLCommands];

    *outList    = [self searchForNopsIn: (unsigned char*)iTextSect.contents
        ofLength: iTextSect.size numFound: outFound];

    return (*outFound != 0);
}

//  searchForNopsIn:ofLength:numFound:
// ----------------------------------------------------------------------------
//  Return value is a newly allocated list of addresses of 'outFound' length.
//  Caller owns the list.

- (unsigned char**)searchForNopsIn: (unsigned char*)inHaystack
                          ofLength: (UInt32)inHaystackLength
                          numFound: (UInt32*)outFound;
{
    unsigned char** foundList       = nil;
    unsigned char*  current;
    unsigned char   searchString[4] = {0x00, 0x55, 0x89, 0xe5};

    *outFound   = 0;

    // Loop thru haystack
    for (current = inHaystack;
         current <= inHaystack + inHaystackLength - 4;
         current++)
    {
        if (memcmp(current, searchString, 4) != 0)
            continue;

        // Match and bail for common benign occurences.
        if (*(current - 4) == 0xe8  ||  // calll
            *(current - 4) == 0xe9  ||  // jmpl
            *(current - 2) == 0xc2)     // ret
            continue;

        // Match and bail for (not) common malignant occurences.
        if (*(current - 7) != 0xe8  &&  // calll
            *(current - 5) != 0xe8  &&  // calll
            *(current - 7) != 0xe9  &&  // jmpl
            *(current - 5) != 0xe9  &&  // jmpl
            *(current - 4) != 0xeb  &&  // jmp
            *(current - 2) != 0xeb  &&  // jmp
            *(current - 5) != 0xc2  &&  // ret
            *(current - 5) != 0xca  &&  // ret
            *(current - 3) != 0xc2  &&  // ret
            *(current - 3) != 0xca  &&  // ret
            *(current - 3) != 0xc3  &&  // ret
            *(current - 3) != 0xcb  &&  // ret
            *(current - 1) != 0xc3  &&  // ret
            *(current - 1) != 0xcb)     // ret
            continue;

        (*outFound)++;
        foundList   = realloc(
            foundList, *outFound * sizeof(unsigned char*));
        foundList[*outFound - 1]    = current;
    }

    return foundList;
}

//  fixNops:toPath:
// ----------------------------------------------------------------------------

- (NSURL*)fixNops: (NopList*)inList
           toPath: (NSString*)inOutputFilePath
{
    if (!inList)
    {
        fprintf(stderr, "otx: -[X86Processor fixNops]: "
            "tried to fix nil NopList.\n");
        return nil;
    }

    if (!inOutputFilePath)
    {
        fprintf(stderr, "otx: -[X86Processor fixNops]: "
            "inOutputFilePath was nil.\n");
        return nil;
    }

    UInt32          i   = 0;
    unsigned char*  item;

    for (i = 0; i < inList->count; i++)
    {
        item    = inList->list[i];

        // For some unknown reason, the following direct memory accesses make
        // the app crash when running inside MallocDebug. Until the cause is
        // found, comment them out when looking for memory leaks.

        // This appears redundant, but to avoid false positives, we must
        // check jumps first(in decreasing size) and return statements last.
        if (*(item - 7) == 0xe8)        // e8xxxxxxxx0000005589e5
        {
            *(item)     = 0x90;
            *(item - 1) = 0x90;
            *(item - 2) = 0x90;
        }
        else if (*(item - 5) == 0xe8)   // e8xxxxxxxx005589e5
        {
            *(item)     = 0x90;
        }
        else if (*(item - 7) == 0xe9)   // e9xxxxxxxx0000005589e5
        {
            *(item)     = 0x90;
            *(item - 1) = 0x90;
            *(item - 2) = 0x90;
        }
        else if (*(item - 5) == 0xe9)   // e9xxxxxxxx005589e5
        {
            *(item)     = 0x90;
        }
        else if (*(item - 4) == 0xeb)   // ebxx0000005589e5
        {
            *(item)     = 0x90;
            *(item - 1) = 0x90;
            *(item - 2) = 0x90;
        }
        else if (*(item - 2) == 0xeb)   // ebxx005589e5
        {
            *(item)     = 0x90;
        }
        else if (*(item - 5) == 0xc2)   // c2xxxx0000005589e5
        {
            *(item)     = 0x90;
            *(item - 1) = 0x90;
            *(item - 2) = 0x90;
        }
        else if (*(item - 5) == 0xca)   // caxxxx0000005589e5
        {
            *(item)     = 0x90;
            *(item - 1) = 0x90;
            *(item - 2) = 0x90;
        }
        else if (*(item - 3) == 0xc2)   // c2xxxx005589e5
        {
            *(item)     = 0x90;
        }
        else if (*(item - 3) == 0xca)   // caxxxx005589e5
        {
            *(item)     = 0x90;
        }
        else if (*(item - 3) == 0xc3)   // c30000005589e5
        {
            *(item)     = 0x90;
            *(item - 1) = 0x90;
            *(item - 2) = 0x90;
        }
        else if (*(item - 3) == 0xcb)   // cb0000005589e5
        {
            *(item)     = 0x90;
            *(item - 1) = 0x90;
            *(item - 2) = 0x90;
        }
        else if (*(item - 1) == 0xc3)   // c3005589e5
        {
            *(item)     = 0x90;
        }
        else if (*(item - 1) == 0xcb)   // cb005589e5
        {
            *(item)     = 0x90;
        }
    }

    // Write data to a new file.
    NSData*     newFile = [NSData dataWithBytesNoCopy: iRAMFile
        length: iRAMFileSize];

    if (!newFile)
    {
        fprintf(stderr, "otx: -[X86Processor fixNops]: "
            "unable to create NSData for new file.\n");
        return nil;
    }

    NSError*    error   = nil;
    NSURL*      newURL  = [[NSURL alloc] initFileURLWithPath:
        [[[inOutputFilePath stringByDeletingLastPathComponent]
        stringByAppendingPathComponent: [[iOFile path] lastPathComponent]]
        stringByAppendingString: @"_fixed"]];

    [newURL autorelease];

    if (![newFile writeToURL: newURL options: NSAtomicWrite error: &error])
    {
        if (error)
            fprintf(stderr, "otx: -[X86Processor fixNops]: "
                "unable to write to new file. %s\n",
                UTF8STRING([error localizedDescription]));
        else
            fprintf(stderr, "otx: -[X86Processor fixNops]: "
                "unable to write to new file.\n");

        return nil;
    }

    // Copy original app's permissions to new file.
    NSFileManager*  fileMan     = [NSFileManager defaultManager];
    NSDictionary*   fileAttrs   = [fileMan fileAttributesAtPath:
        [iOFile path] traverseLink: NO];

    if (!fileAttrs)
    {
        fprintf(stderr, "otx: -[X86Processor fixNops]: "
            "unable to read attributes from executable.\n");
        return nil;
    }

    NSDictionary*   permsDict   = [NSDictionary dictionaryWithObjectsAndKeys:
        [NSNumber numberWithUnsignedInt: [fileAttrs filePosixPermissions]],
        NSFilePosixPermissions, nil];

    if (![fileMan changeFileAttributes: permsDict atPath: [newURL path]])
    {
        fprintf(stderr, "otx: -[X86Processor fixNops]: "
            "unable to change file permissions for fixed executable.\n");
    }

    // Return fixed file.
    return newURL;
}

@end
