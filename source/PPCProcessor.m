#import <libkern/OSByteOrder.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/swap.h>
#import <objc/objc-runtime.h>
#import <sys/ptrace.h>
#import <sys/syscall.h>

#import "PPCProcessor.h"
#import "SyscallStrings.h"
#import "UserDefaultKeys.h"

// ============================================================================

@implementation PPCProcessor

// A subclass of ExeProcessor that handles PPC-specific issues.

//	initWithURL:progText:progBar:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (id)initWithURL: (NSURL*)inURL
		 progText: (NSTextField*)inText
		  progBar: (NSProgressIndicator*)inProg
{
	if ((self = [super initWithURL: inURL
		progText: inText progBar: inProg]) == nil)
		return nil;

	strncpy(mArchString, "-arch ppc", 10);

	mFieldWidths.offset			= 8;
	mFieldWidths.address		= 10;
	mFieldWidths.instruction	= 10;
	mFieldWidths.mnemonic		= 9;
	mFieldWidths.operands		= 17;

	return self;
}

//	loadDyldDataSection:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)loadDyldDataSection: (section*)inSect
{
	[super loadDyldDataSection: inSect];

	if (!mAddrDyldStubBindingHelper)
		return;

	mAddrDyldFuncLookupPointer	= mAddrDyldStubBindingHelper + 24;
}

//	codeFromLine:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)codeFromLine: (Line*)inLine
{
	UInt32	theInstruction	= *(UInt32*)
		((char*)mMachHeader + (inLine->info.address - mTextOffset));

	if (mSwapped)
		theInstruction	= OSSwapInt32(theInstruction);

	snprintf(inLine->info.code, 10, "%08x", theInstruction);
}

//	commentForLine:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)commentForLine: (Line*)inLine;
{
	UInt32	theCode	= strtoul(inLine->info.code, nil, 16);

	if (mSwapped)
		OSSwapInt32(theCode);

	char*	theDummyPtr	= nil;
	char*	theSymPtr	= nil;
	UInt8	opcode		= PO(theCode);
	UInt32	localAddy;

	mLineCommentCString[0]	= 0;

// Examine the primary opcode to see if we need to look for comments. The
// following switch statement checks most of the cases in which otool calls
// print_immediate(), excluding some uncommon cases.

//	0x07 mulli
//	0x08 subfic
//	0x0c addic
//	0x0d addic.
//	0x21 lwzu
//	0x23 lbzu
//	0x25 stwu
//	0x27 stbu
//	0x29 lhzu
//	0x2a lha
//	0x2b lhau
//	0x2d sthu

	switch (opcode)
	{
		case 0x0a:	// cmpli | cmplwi	UIMM
		case 0x0b:	// cmpi | cmpwi		SIMM
		{
			SInt16	imm	= SIMM(theCode);

			// Check for a single printable 7-bit char.
			if (imm >= 0x20 && imm < 0x7f)
				snprintf(mLineCommentCString, 4, "'%c'", imm);

			break;
		}

		case 0x11:	// sc
			CommentForSystemCall();

			break;

		// Check for absolute branches to the ObjC runtime page. Similar to
		// the comm page behavior described at
		// http://darwinsource.opendarwin.org/10.4.6.ppc/xnu-792.6.70/osfmk/ppc/cpu_capabilities.h
		// However, the ObjC runtime page is not really a comm page, and it
		// cannot be accessed by bca and bcla instructions, due to their
		// 16-bit limitation.
		case 0x12:	// b, ba, bl, bla
		{
			// ignore non-absolute branches
			if (!AA(theCode))
				break;

			UInt32	target	= LI(theCode) | 0xfc000000;

			switch (target)
			{
				case kRTAddress_objc_msgSend:
					strncpy(mLineCommentCString, kRTName_objc_msgSend,
						strlen(kRTName_objc_msgSend) + 1);
					break;
				case kRTAddress_objc_assign_ivar:
					strncpy(mLineCommentCString, kRTName_objc_assign_ivar,
						strlen(kRTName_objc_assign_ivar) + 1);
					break;
				case kRTAddress_objc_assign_global:
					strncpy(mLineCommentCString, kRTName_objc_assign_global,
						strlen(kRTName_objc_assign_global) + 1);
					break;
				case kRTAddress_objc_assign_strongCast:
					strncpy(mLineCommentCString, kRTName_objc_assign_strongCast,
						strlen(kRTName_objc_assign_strongCast) + 1);
					break;

				default:
					break;
			}

			break;
		}

		case 0x13:	// bcctr, bclr, isync
		{
			if (SO(theCode) != 528)		// bcctr
				break;

			// Print value of ctr, ignoring the low 2 bits.
			if (mCTR.isValid)
				snprintf(mLineCommentCString, 10, "0x%x",
					mCTR.intValue & ~3);

			break;
		}

		case 0x30:	// lfs		SIMM
		case 0x34:	// stfs		SIMM
		case 0x32:	// lfd		SIMM
		case 0x36:	// stfd		SIMM
		{
			if (!mRegInfos[RA(theCode)].isValid || RA(theCode) == 0)
				break;

			if (mRegInfos[RA(theCode)].classPtr)
			{	// search instance vars
				objc_ivar	theIvar	= {0};

				if (!FindIvar(&theIvar, mRegInfos[RA(theCode)].classPtr,
					UIMM(theCode)))
					break;

				theSymPtr	= GetPointer(
					(UInt32)theIvar.ivar_name, nil);

				if (theSymPtr)
				{
					if (mShowIvarTypes)
					{
						char	theTypeCString[200]	=	{0};

						GetDescription(theTypeCString,
							GetPointer((UInt32)theIvar.ivar_type, nil));

						snprintf(mLineCommentCString,
							MAX_COMMENT_LENGTH - 1, "(%s)%s",
							theTypeCString, theSymPtr);
					}
					else
						snprintf(mLineCommentCString,
							MAX_COMMENT_LENGTH - 1, "%s", theSymPtr);
				}
			}
			else
			{
				localAddy	= mRegInfos[RA(theCode)].intValue + SIMM(theCode);
				theDummyPtr	= GetPointer(localAddy, nil);

				if (!theDummyPtr)
					break;

				if (opcode == 0x32 || opcode == 0x36)	// lfd | stfd
				{
					UInt64	theInt64	= *(UInt64*)theDummyPtr;

					if (mSwapped)
						theInt64	= OSSwapInt64(theInt64);

					// dance around printf's type coersion...
					double*	theDoublePtr	= (double*)&theInt64;

					snprintf(mLineCommentCString,
						30, "%lG", *theDoublePtr);
				}
				else	// lfs | stfs
				{
					UInt32	theInt32	= *(UInt32*)theDummyPtr;

					if (mSwapped)
						theInt32	= OSSwapInt32(theInt32);

					// dance around printf's type coersion...
					float*	theFloatPtr	= (float*)&theInt32;

					snprintf(mLineCommentCString,
						30, "%G", *theFloatPtr);
				}
			}

			break;
		}

		case 0x0e:	// li | addi	SIMM
		case 0x18:	// ori			UIMM
		case 0x20:	// lwz			SIMM
		case 0x22:	// lbz			SIMM
		case 0x24:	// stw			SIMM
		case 0x26:	// stb			SIMM
		case 0x28:	// lhz			SIMM
		case 0x2c:	// sth			SIMM
		{
			if (!mRegInfos[RA(theCode)].isValid || RA(theCode) == 0)
				break;

			if (mRegInfos[RA(theCode)].classPtr)	// relative to a class
			{	// search instance vars
				objc_ivar	theIvar	= {0};

				if (!FindIvar(&theIvar, mRegInfos[RA(theCode)].classPtr,
					UIMM(theCode)))
					break;

				theSymPtr	= GetPointer(
					(UInt32)theIvar.ivar_name, nil);

				if (theSymPtr)
				{
					if (mShowIvarTypes)
					{
						char	theTypeCString[200]	=	{0};

						GetDescription(theTypeCString,
							GetPointer((UInt32)theIvar.ivar_type, nil));

						snprintf(mLineCommentCString,
							MAX_COMMENT_LENGTH - 1, "(%s)%s",
							theTypeCString, theSymPtr);
					}
					else
						snprintf(mLineCommentCString,
							MAX_COMMENT_LENGTH - 1, "%s", theSymPtr);
				}

				// class vars? haven't seen any...

			}
			else	// absolute address
			{
				if (opcode == 0x18)	// ori		UIMM
					localAddy	= mRegInfos[RA(theCode)].intValue |
						UIMM(theCode);
				else
					localAddy	= mRegInfos[RA(theCode)].intValue +
						SIMM(theCode);

				UInt8	theType	= PointerType;
				UInt32	theValue;

				theSymPtr	= GetPointer(localAddy, &theType);

				if (theSymPtr)
				{
					switch (theType)
					{
						case DataGenericType:
							theValue	= *(UInt32*)theSymPtr;

							if (mSwapped)
								theValue	= OSSwapInt32(theValue);

							theDummyPtr	= GetPointer(theValue, &theType);

							switch (theType)
							{
								case PointerType:
									theSymPtr	= theDummyPtr;
									break;

								default:
									theSymPtr	= nil;
									break;
							}

							break;

						case DataConstType:
							theSymPtr	= nil;
							break;

// See http://darwinsource.opendarwin.org/Current/Csu-57/dyld.s
// They hardcoded the values, we may as well...
						case DYLDType:
						{
							char*	dyldComment	= nil;

							theValue	= *(UInt32*)theSymPtr;

							if (mSwapped)
								theValue	= OSSwapInt32(theValue);

							switch(theValue)
							{
								case kDyldAddress_LaSymBindingEntry:
									dyldComment	= kDyldName_LaSymBindingEntry;
									break;
								case kDyldAddress_FuncLookupPointer:
									dyldComment	= kDyldName_FuncLookupPointer;
									break;

								default:
									break;
							}

							if (dyldComment)
								strcpy(mLineCommentCString, dyldComment);

							break;
						}

						case PointerType:
							break;

						case CFStringType:
						{
							cf_string_object	theCFString	= 
								*(cf_string_object*)theSymPtr;

							if (theCFString.oc.length == 0)
							{
								theSymPtr	= nil;
								break;
							}

							if (mSwapped)
								theCFString.oc.chars	= (char*)
									OSSwapInt32((UInt32)theCFString.oc.chars);

							theSymPtr	= GetPointer(
								(UInt32)theCFString.oc.chars, nil);

							break;
						}

						case ImpPtrType:
						case NLSymType:
						{
							theValue	= *(UInt32*)theSymPtr;

							if (mSwapped)
								theValue	= OSSwapInt32(theValue);

							theDummyPtr	= GetPointer(theValue, nil);

							if (!theDummyPtr)
							{
								theSymPtr	= nil;
								break;
							}

							theValue	= *(UInt32*)(theDummyPtr + 4);

							if (mSwapped)
								theValue	= OSSwapInt32(theValue);

							if (theValue != typeid_NSString)
							{
								theValue	= *(UInt32*)theDummyPtr;

								if (mSwapped)
									theValue	= OSSwapInt32(theValue);

								theDummyPtr	= GetPointer(theValue, nil);

								if (!theDummyPtr)
								{
									theSymPtr	= nil;
									break;
								}
							}

							cf_string_object	theCFString	= 
								*(cf_string_object*)theDummyPtr;

							if (theCFString.oc.length == 0)
							{
								theSymPtr	= nil;
								break;
							}

							if (mSwapped)
								theCFString.oc.chars	= (char*)
									OSSwapInt32((UInt32)theCFString.oc.chars);

							theSymPtr	= GetPointer(
								(UInt32)theCFString.oc.chars, nil);

							break;
						}

						case OCGenericType:
						case OCStrObjectType:
						case OCClassType:
						case OCModType:
							theDummyPtr	= [self objcDescriptionFromObject:
								theSymPtr type: theType];

							if (theDummyPtr)
							{
								switch (theType)
								{
									case OCClassType:
										mRegInfos[RT(theCode)].classPtr	=
											(objc_class*)theSymPtr;
										break;

									default:
										break;
								}
							}

							theSymPtr	= theDummyPtr;
							break;

						default:
							break;
					}

					if (theSymPtr && !mLineCommentCString[0])
					{
						if (theType == PStringType)
							snprintf(mLineCommentCString, 255,
								"%*s", theSymPtr[0], theSymPtr + 1);
						else
							snprintf(mLineCommentCString,
								MAX_COMMENT_LENGTH - 1, "%s", theSymPtr);
					}
				}	// if (theSymPtr)
				else
				{	// Maybe it's a four-char code...
					if ((opcode == 0x0e || opcode == 0x18) &&	// li | addi | ori
						localAddy >= 0x20202020 && localAddy < 0x7f7f7f7f)
					{
						if (mSwapped)
							localAddy	= OSSwapInt32(localAddy);

						char*	fcc	= (char*)&localAddy;

						if (fcc[0] >= 0x20 && fcc[0] < 0x7f &&
							fcc[1] >= 0x20 && fcc[1] < 0x7f &&
							fcc[2] >= 0x20 && fcc[2] < 0x7f &&
							fcc[3] >= 0x20 && fcc[3] < 0x7f)
							snprintf(mLineCommentCString,
								7, "'%.4s'", fcc);
					}
				}
			}	// if !(.classPtr)

			break;
		}	// case 0x0e...

		default:
			break;
	}
}

//	commentForSystemCall
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ
//	System call number is stored in r0, possible values defined in
//	<sys/syscall.h>. Call numbers are indices into a lookup table of handler
//	routines. Args being passed to the looked-up handler start at r3 or r4,
//	depending on whether it's an indirect SYS_syscall.

- (void)commentForSystemCall
{
	if (!mRegInfos[0].isValid ||
		 mRegInfos[0].intValue > SYS_MAXSYSCALL)
		return;

	BOOL	isIndirect		= (mRegInfos[0].intValue == SYS_syscall);
	UInt32	syscallNumReg	= isIndirect ? 3 : 0;
	UInt32	syscallArg1Reg	= isIndirect ? 4 : 3;

	char*	theSysString	= gSysCalls[mRegInfos[syscallNumReg].intValue];

	if (!theSysString)
		return;

	char	theTempComment[50]	= {0};

	strncpy(theTempComment, theSysString, strlen(theSysString) + 1);

	// Handle various system calls.
	switch (mRegInfos[syscallNumReg].intValue)
	{
		case SYS_ptrace:
			if (mRegInfos[syscallArg1Reg].isValid &&
				mRegInfos[syscallArg1Reg].intValue == PT_DENY_ATTACH)
				snprintf(mLineCommentCString, 40, "%s(%s)",
					theTempComment, "PT_DENY_ATTACH");
			else
				strncpy(mLineCommentCString, theTempComment,
					strlen(theTempComment) + 1);

			break;

		default:
			strncpy(mLineCommentCString, theTempComment,
				strlen(theTempComment) + 1);

			break;
	}
}

//	chooseLine:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (void)chooseLine: (Line**)ioLine
{
	if (!(*ioLine) || !(*ioLine)->info.isCode || !(*ioLine)->alt)
		return;

	UInt32	theCode	= strtoul(
		(const char*)(*ioLine)->info.code, nil, 16);

	if (PO(theCode) == 18	&&	// b, ba, bl, bla
		(*ioLine)->alt->chars)
	{
		Line*	theNewLine	= malloc(sizeof(Line));

		memcpy(theNewLine, (*ioLine)->alt, sizeof(Line));
		theNewLine->chars	= malloc(theNewLine->length + 1);
		strncpy(theNewLine->chars, (*ioLine)->alt->chars,
			theNewLine->length + 1);

		ReplaceLine(*ioLine, theNewLine, &mPlainLineListHead);
		*ioLine	= theNewLine;
	}
}

//	updateRegisters:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ
//	Keep our local copy of the GPRs in sync as much as possible with the
//	values that the exe will use at runtime. Assign classPtr and catPtr fields
//	in a register's info if its new value points to a class or category.
// http://developer.apple.com/documentation/DeveloperTools/Conceptual/LowLevelABI/Articles/32bitPowerPC.html
// http://developer.apple.com/documentation/DeveloperTools/Conceptual/MachOTopics/Articles/dynamic_code.html

- (void)updateRegisters: (Line*)inLine;
{
	// inLine = nil if this is 1st line of a function. Setup the registers
	// with default info. r3 is 'self' at the beginning of any Obj-C method,
	// and r12 holds the address of the 1st instruction if the function was
	// called indirectly. In the case of direct calls, r12 will be overwritten
	// before it is used, if it is used at all.
	if (!inLine)
	{
		bzero(&mRegInfos[0], sizeof(RegisterInfo) * 32);

		mRegInfos[3].classPtr	= mCurrentClass;
		mRegInfos[3].catPtr		= mCurrentCat;
		mRegInfos[3].isValid	= true;
		mRegInfos[12].intValue	= mCurrentFuncPtr;
		mRegInfos[12].isValid	= true;
		bzero(&mLR, sizeof(RegisterInfo));
		bzero(&mCTR, sizeof(RegisterInfo));

		if (mLocalSelves)
		{
			free(mLocalSelves);
			mLocalSelves	= nil;
			mNumLocalSelves	= 0;
		}

		return;
	}

	UInt32	theNewValue;
	UInt32	theCode		= strtoul(
		(const char*)inLine->info.code, nil, 16);

	if (IS_BRANCH_LINK(theCode))
	{
		mLR.intValue	= inLine->info.address + 4;
		mLR.isValid		= true;
	}

	switch (PO(theCode))
	{
		case 0x07:	// mulli		SIMM
		{
			if (!mRegInfos[RA(theCode)].isValid)
			{
				bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
				break;
			}

			UInt64	theProduct	=
				(SInt32)mRegInfos[RA(theCode)].intValue * SIMM(theCode);

			bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
			mRegInfos[RT(theCode)].intValue	= theProduct & 0xffffffff;
			mRegInfos[RT(theCode)].isValid	= true;

			break;
		}

		case 0x08:	// subfic		SIMM
			if (!mRegInfos[RA(theCode)].isValid)
			{
				bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
				break;
			}

			theNewValue	= mRegInfos[RA(theCode)].intValue - SIMM(theCode);

			bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
			mRegInfos[RT(theCode)].intValue	= theNewValue;
			mRegInfos[RT(theCode)].isValid	= true;

			break;

		case 0x0c:	// addic		SIMM
		case 0x0d:	// addic.		SIMM
		case 0x0e:	// addi | li	SIMM
			// Check for copied self pointer. This happens mostly in "init"
			// methods, as in: "self = [super init]"
			if (mLocalSelves		&&	// self was copied to a local variable
				RA(theCode) == 1	&&	// current reg is stack pointer (r1)
				SIMM(theCode) >= 0)		// we're accessing local vars, not args
			{
				UInt32	i;

				for (i = 0; i < mNumLocalSelves; i++)
				{
					// If we're accessing a local var copy of self...
					if (mLocalSelves[i].localAddress == UIMM(theCode))
					{
						// ... copy that info back to the reg in question
						bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
						mRegInfos[RT(theCode)]	= mLocalSelves[i].regInfo;

						// and split.
						break;
					}
				}

				break;
			}

			if (RA(theCode) == 0)	// li
			{
				bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
				mRegInfos[RT(theCode)].intValue	= UIMM(theCode);
				mRegInfos[RT(theCode)].isValid	= true;
			}
			else					// addi
			{
				// Update rD if we know what rA is.
				if (!mRegInfos[RA(theCode)].isValid)
				{
					bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
					break;
				}

				mRegInfos[RT(theCode)].classPtr	= nil;
				mRegInfos[RT(theCode)].catPtr	= nil;

				theNewValue	= mRegInfos[RA(theCode)].intValue + SIMM(theCode);

				bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
				mRegInfos[RT(theCode)].intValue	= theNewValue;
				mRegInfos[RT(theCode)].isValid	= true;
			}

			break;

		case 0x0f:	// addis | lis
			mRegInfos[RT(theCode)].classPtr	= nil;
			mRegInfos[RT(theCode)].catPtr	= nil;

			if (RA(theCode) == 0)	// lis
			{
				bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
				mRegInfos[RT(theCode)].intValue	=
					UIMM(theCode) << 16;
				mRegInfos[RT(theCode)].isValid	= true;
				break;
			}

			if (!mRegInfos[RA(theCode)].isValid)	// addis
			{
				bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
				break;
			}

			theNewValue	= mRegInfos[RA(theCode)].intValue +
				(SIMM(theCode) << 16);

			bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
			mRegInfos[RT(theCode)].intValue	= theNewValue;
			mRegInfos[RT(theCode)].isValid	= true;

			break;

		case 0x15:	// rlwinm
		{
			if (!mRegInfos[RT(theCode)].isValid)
			{
				bzero(&mRegInfos[RA(theCode)], sizeof(RegisterInfo));
				break;
			}

			UInt32	rotatedRT	=
				rotl(mRegInfos[RT(theCode)].intValue, RB(theCode));
			UInt32	theMask		= 0x0;
			UInt8	i;

			for (i = MB(theCode); i <= ME(theCode); i++)
				theMask	|= 1 << (31 - i);

			theNewValue	= rotatedRT & theMask;

			bzero(&mRegInfos[RA(theCode)], sizeof(RegisterInfo));
			mRegInfos[RA(theCode)].intValue	= theNewValue;
			mRegInfos[RA(theCode)].isValid	= true;

			break;
		}

		case 0x18:	// ori
			if (!mRegInfos[RT(theCode)].isValid)
			{
				bzero(&mRegInfos[RA(theCode)], sizeof(RegisterInfo));
				break;
			}

			theNewValue	=
				mRegInfos[RT(theCode)].intValue	| (UInt32)UIMM(theCode);

			bzero(&mRegInfos[RA(theCode)], sizeof(RegisterInfo));
			mRegInfos[RA(theCode)].intValue	= theNewValue;
			mRegInfos[RA(theCode)].isValid	= true;

			break;

		case 0x1f:
			switch (SO(theCode))
			{
				case 23:	// lwzx
					bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
					break;

				case 8:		// subfc
				case 40:	// subf
					if (!mRegInfos[RA(theCode)].isValid ||
						!mRegInfos[RB(theCode)].isValid)
					{
						bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
						break;
					}

					// 2's complement subtraction
					theNewValue	=
						(mRegInfos[RA(theCode)].intValue ^= 0xffffffff) +
						mRegInfos[RB(theCode)].intValue + 1;

					bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));
					mRegInfos[RT(theCode)].intValue	= theNewValue;
					mRegInfos[RT(theCode)].isValid	= true;

					break;

				case 339:	// mfspr
					bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));

					if (SPR(theCode) == LR)	// from LR
					{	// Copy LR into rD.
						mRegInfos[RT(theCode)].intValue	= mLR.intValue;
						mRegInfos[RT(theCode)].isValid	= true;
					}

					break;

				case 444:	// or | or.
					if (!mRegInfos[RT(theCode)].isValid ||
						!mRegInfos[RB(theCode)].isValid)
					{
						bzero(&mRegInfos[RA(theCode)], sizeof(RegisterInfo));
						break;
					}

					theNewValue	=
						(mRegInfos[RT(theCode)].intValue |
						 mRegInfos[RB(theCode)].intValue);

					bzero(&mRegInfos[RA(theCode)], sizeof(RegisterInfo));
					mRegInfos[RA(theCode)].intValue	= theNewValue;
					mRegInfos[RA(theCode)].isValid	= true;

					// If we just copied a register, copy the
					// remaining fields.
					if (RT(theCode) == RB(theCode))
					{
						mRegInfos[RA(theCode)].classPtr	=
						mRegInfos[RB(theCode)].classPtr;
						mRegInfos[RA(theCode)].catPtr	=
						mRegInfos[RB(theCode)].catPtr;
					}

					break;

				case 467:	// mtspr
					if (SPR(theCode) == CTR)	// to CTR
					{
						if (!mRegInfos[RS(theCode)].isValid)
						{
							bzero(&mCTR, sizeof(RegisterInfo));
							break;
						}

						mCTR.intValue	= mRegInfos[RS(theCode)].intValue;
						mCTR.isValid	= true;
					}

					break;

				case 536:	// srw
					if (!mRegInfos[RS(theCode)].isValid	||
						!mRegInfos[RB(theCode)].isValid)
					{
						bzero(&mRegInfos[RA(theCode)], sizeof(RegisterInfo));
						break;
					}

					theNewValue	=
						mRegInfos[RS(theCode)].intValue >>
						(mRegInfos[RB(theCode)].intValue & 0x1f);

					bzero(&mRegInfos[RA(theCode)], sizeof(RegisterInfo));
					mRegInfos[RA(theCode)].intValue	= theNewValue;
					mRegInfos[RA(theCode)].isValid	= true;

					break;

				default:
					break;
			}

			break;

		case 0x20:	// lwz
		case 0x22:	// lbz
		{
			bzero(&mRegInfos[RT(theCode)], sizeof(RegisterInfo));

			if (RA(theCode) == 0)
			{
				mRegInfos[RT(theCode)].intValue	= SIMM(theCode);
				mRegInfos[RT(theCode)].isValid	= true;
			}

			break;
		}

		case 0x24:	// stw
			if (!mRegInfos[RT(theCode)].isValid		||	// only if it's a class
				!mRegInfos[RT(theCode)].classPtr	||	//  being copied to
				RA(theCode) != 1					||	// a local variable,
				SIMM(theCode) < 0)						// not an argument
				break;

			mNumLocalSelves++;

			if (mLocalSelves)
				mLocalSelves	= realloc(mLocalSelves,
					mNumLocalSelves * sizeof(LocalVarInfo));
			else
				mLocalSelves	= malloc(sizeof(LocalVarInfo));

			mLocalSelves[mNumLocalSelves - 1]	= (LocalVarInfo)
				{mRegInfos[RT(theCode)], UIMM(theCode)};

			break;

/*		case 0x21:
		case 0x23:
		case 0x25:
		case 0x26:
		case 0x27:
		case 0x28:
		case 0x29:
		case 0x2a:
		case 0x2b:
		case 0x2c:
		case 0x2d:
		case 0x2e:
		case 0x2f:
			break;*/

		default:
			break;
	}
}

//	lineIsFunction:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (BOOL)lineIsFunction: (Line*)inLine
{
	if (!inLine)
		return false;

	MethodInfo*	theDummyInfo	= nil;
	UInt32		theAddy			= inLine->info.address;

	if (theAddy == mAddrDyldStubBindingHelper)
		return true;

	if (theAddy == mAddrDyldFuncLookupPointer)
		return true;

	// In Obj-C apps, the majority of funcs will have Obj-C symbols, so check
	// those first.
	if (FindClassMethodByAddress(&theDummyInfo, theAddy))
		return true;

	if (FindCatMethodByAddress(&theDummyInfo, theAddy))
		return true;

	// If it's not an Obj-C method, maybe there's an nlist.
	if (FindSymbolByAddress(theAddy))
		return true;

	BOOL	isFunction	= false;
	UInt32	theCode		= strtoul(
		(const char*)&inLine->info.code, nil, 16);

	if ((theCode & 0x7c0807ff) == 0x7c0802a6)	// mflr to any reg
	{	// Allow for late mflr
		BOOL	foundUB	= false;
		Line*	thePrevLine	= inLine->prev;

		// Walk back to the most recent unconditional branch, looking
		// for existing symbols.
		while (!foundUB && thePrevLine)
		{
			// Allow for multiple mflr's
			if (thePrevLine->info.isFunction)
				return false;

			theCode	= strtoul(
				(const char*)&thePrevLine->info.code, nil, 16);

			UInt8	opcode	= PO(theCode);

			if (opcode == 16 || opcode == 18 || opcode == 19)
			// bc, bca, bcl, bcla, b, ba, bl, bla, bclr, bclrl and more
			{
				if (!IS_BRANCH_CONDITIONAL(theCode) &&
					theCode != 0x429f0005 &&	// bcl w/ "always branch"
					(theCode & 0x48000001) != 0x48000001)	 // bl
					foundUB	= true;
			}

			if (!foundUB)
				thePrevLine = thePrevLine->prev;
		}

		if (!thePrevLine)
			return true;

		thePrevLine	= thePrevLine->next;

		// If the code line following the most recent unconditional
		// branch is not already recognized, flag it now.
		if (thePrevLine == inLine)
			isFunction	= true;
		else
		{
			BOOL	foundStart	= false;

			for (; thePrevLine != inLine;
				thePrevLine = thePrevLine->next)
			{
				if (!thePrevLine->info.isCode)
					continue;	// not code, keep looking
				else if (!thePrevLine->info.isFunction)
				{				// not yet recognized, try it
					theCode	= strtoul(
						(const char*)&thePrevLine->info.code, nil, 16);

					if (theCode == 0x7fe00008	||	// ignore traps
						theCode == 0x60000000	||	// ignore nops
						theCode == 0x00000000)		// ignore .longs
						continue;
					else
					{
						thePrevLine->info.isFunction	= true;
						foundStart	= true;
						break;
					}
				}
				else	// already recognized, bail
				{
					foundStart	= true;
					break;
				}
			}

			if (!foundStart)
				isFunction	= true;
		}
	}	// if (theCode == 0x7c0802a6)

	return isFunction;
}

@end
