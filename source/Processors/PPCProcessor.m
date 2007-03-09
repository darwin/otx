/*
	PPCProcessor.m

	A subclass of ExeProcessor that handles PPC-specific issues.

	This file is in the public domain.
*/

#import "PPCProcessor.h"
#import "ArchSpecifics.h"
#import "ListUtils.h"
#import "ObjcAccessors.h"
#import "ObjectLoader.h"
#import "SyscallStrings.h"
#import "UserDefaultKeys.h"

// ============================================================================

@implementation PPCProcessor

//	initWithURL:controller:andOptions:
// ----------------------------------------------------------------------------

- (id)initWithURL: (NSURL*)inURL
	   controller: (id)inController
		  options: (ProcOptions*)inOptions;
{
	if ((self = [super initWithURL: inURL
		controller: inController options: inOptions]))
	{
		strncpy(mArchString, "ppc", 4);

		mArchSelector				= CPU_TYPE_POWERPC;
		mFieldWidths.offset			= 8;
		mFieldWidths.address		= 10;
		mFieldWidths.instruction	= 10;
		mFieldWidths.mnemonic		= 9;
		mFieldWidths.operands		= 17;
	}

	return self;
}

//	loadDyldDataSection:
// ----------------------------------------------------------------------------

- (void)loadDyldDataSection: (section*)inSect
{
	[super loadDyldDataSection: inSect];

	if (!mAddrDyldStubBindingHelper)
		return;

	mAddrDyldFuncLookupPointer	= mAddrDyldStubBindingHelper + 24;
}

//	codeFromLine:
// ----------------------------------------------------------------------------

- (void)codeFromLine: (Line*)inLine
{
	UInt32	theInstruction	= (mMachHeader.filetype == MH_OBJECT) ?
		*(UInt32*)((char*)mMachHeaderPtr +
		(inLine->info.address + mTextOffset)) :
		*(UInt32*)((char*)mMachHeaderPtr +
		(inLine->info.address - mTextOffset));

	if (mSwapped)
		theInstruction	= OSSwapInt32(theInstruction);

	snprintf(inLine->info.code, 10, "%08x", theInstruction);
}

#pragma mark -
//	commentForLine:
// ----------------------------------------------------------------------------

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

	// Examine the primary opcode to see if we need to look for comments.
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
		// http://www.opensource.apple.com/darwinsource/10.4.7.ppc/xnu-792.6.76/osfmk/ppc/cpu_capabilities.h
		// However, the ObjC runtime page is not really a comm page, and it
		// cannot be accessed by bca and bcla instructions, due to their
		// 16-bit limitation.
		case 0x12:	// b, ba, bl, bla
		{
			// ignore non-absolute branches
			if (!AA(theCode))
				break;

			UInt32	target	= LI(theCode);

			switch (target)
			{
				case kRTAddress_objc_msgSend:
				{
					char	tempComment[MAX_COMMENT_LENGTH];

					strncpy(tempComment, kRTName_objc_msgSend,
						strlen(kRTName_objc_msgSend) + 1);

					if (mOpts.verboseMsgSends)
						CommentForMsgSendFromLine(tempComment, inLine);

					strncpy(mLineCommentCString, tempComment,
						strlen(tempComment) + 1);

					break;
				}

				case kRTAddress_objc_assign_ivar:
				{
					char	tempComment[MAX_COMMENT_LENGTH];

					strncpy(tempComment, kRTName_objc_assign_ivar,
						strlen(kRTName_objc_assign_ivar) + 1);

					if (mRegInfos[5].isValid)
					{
						objc_ivar	theIvar			= {0};
						objc_class	swappedClass	= *mCurrentClass;

						if (mSwapped)
							swap_objc_class(&swappedClass);

						if (!mIsInstanceMethod)
						{
							if (!GetObjcMetaClassFromClass(
								&swappedClass, &swappedClass))
								break;

							if (mSwapped)
								swap_objc_class(&swappedClass);
						}

						if (!FindIvar(&theIvar,
							&swappedClass, mRegInfos[5].value))
						{
							strncpy(mLineCommentCString, tempComment,
								strlen(tempComment) + 1);
							break;
						}

						theSymPtr	= GetPointer(
							(UInt32)theIvar.ivar_name, nil);

						if (!theSymPtr)
						{
							strncpy(mLineCommentCString, tempComment,
								strlen(tempComment) + 1);
							break;
						}

						if (mOpts.variableTypes)
						{
							char	theTypeCString[MAX_TYPE_STRING_LENGTH];

							theTypeCString[0]	= 0;

							GetDescription(theTypeCString,
								GetPointer((UInt32)theIvar.ivar_type, nil));
							snprintf(mLineCommentCString,
								MAX_COMMENT_LENGTH - 1, "%s (%s)%s",
								tempComment, theTypeCString, theSymPtr);
						}
						else
							snprintf(mLineCommentCString,
								MAX_COMMENT_LENGTH - 1, "%s %s",
								tempComment, theSymPtr);
					}
					else	// !mReginfos[5].isValid
						strncpy(mLineCommentCString, tempComment,
							strlen(tempComment) + 1);

					break;
				}

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
			if (SO(theCode) != 528)	// bcctr
				break;

			// Print value of ctr, ignoring the low 2 bits.
			if (mCTR.isValid)
				snprintf(mLineCommentCString, 10, "0x%x",
					mCTR.value & ~3);

			break;

		case 0x30:	// lfs		SIMM
		case 0x34:	// stfs		SIMM
		case 0x32:	// lfd		SIMM
		case 0x36:	// stfd		SIMM
		{
			if (!mRegInfos[RA(theCode)].isValid || RA(theCode) == 0)
				break;

			if (mRegInfos[RA(theCode)].classPtr)
			{	// search instance vars
				objc_ivar	theIvar			= {0};
				objc_class	swappedClass	=
					*mRegInfos[RA(theCode)].classPtr;

				if (!mIsInstanceMethod)
				{
					if (!GetObjcMetaClassFromClass(
						&swappedClass, &swappedClass))
						break;

					if (mSwapped)
						swap_objc_class(&swappedClass);
				}

				if (!FindIvar(&theIvar, &swappedClass, UIMM(theCode)))
					break;

				theSymPtr	= GetPointer(
					(UInt32)theIvar.ivar_name, nil);

				if (theSymPtr)
				{
					if (mOpts.variableTypes)
					{
						char	theTypeCString[MAX_TYPE_STRING_LENGTH];

						theTypeCString[0]	= 0;

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
				localAddy	= mRegInfos[RA(theCode)].value + SIMM(theCode);
				theDummyPtr	= GetPointer(localAddy, nil);

				if (!theDummyPtr)
					break;

				if (opcode == 0x32 || opcode == 0x36)	// lfd | stfd
				{
					UInt64	theInt64	= *(UInt64*)theDummyPtr;

					if (mSwapped)
						theInt64	= OSSwapInt64(theInt64);

					// dance around printf's type coersion
					snprintf(mLineCommentCString,
						30, "%lG", *(double*)&theInt64);
				}
				else	// lfs | stfs
				{
					UInt32	theInt32	= *(UInt32*)theDummyPtr;

					if (mSwapped)
						theInt32	= OSSwapInt32(theInt32);

					// dance around printf's type coersion
					snprintf(mLineCommentCString,
						30, "%G", *(float*)&theInt32);
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
				objc_ivar	theIvar		= {0};
				objc_class	swappedClass	=
					*mRegInfos[RA(theCode)].classPtr;

				if (!mIsInstanceMethod)
				{
					if (!GetObjcMetaClassFromClass(
						&swappedClass, &swappedClass))
						break;

					if (mSwapped)
						swap_objc_class(&swappedClass);
				}

				if (!FindIvar(&theIvar, &swappedClass, UIMM(theCode)))
					break;

				theSymPtr	= GetPointer(
					(UInt32)theIvar.ivar_name, nil);

				if (theSymPtr)
				{
					if (mOpts.variableTypes)
					{
						char	theTypeCString[MAX_TYPE_STRING_LENGTH];

						theTypeCString[0]	= 0;

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
			else	// absolute address
			{
				if (opcode == 0x18)	// ori		UIMM
					localAddy	= mRegInfos[RA(theCode)].value |
						UIMM(theCode);
				else
					localAddy	= mRegInfos[RA(theCode)].value +
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

// See http://www.opensource.apple.com/darwinsource/10.4.7.ppc/Csu-58/dyld.s
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

							if (theCFString.oc_string.length == 0)
							{
								theSymPtr	= nil;
								break;
							}

							if (mSwapped)
								theCFString.oc_string.chars	=
									(char*)OSSwapInt32(
									(UInt32)theCFString.oc_string.chars);

							theSymPtr	= GetPointer(
								(UInt32)theCFString.oc_string.chars, nil);

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

							if (theCFString.oc_string.length == 0)
							{
								theSymPtr	= nil;
								break;
							}

							if (mSwapped)
								theCFString.oc_string.chars	=
									(char*)OSSwapInt32(
									(UInt32)theCFString.oc_string.chars);

							theSymPtr	= GetPointer(
								(UInt32)theCFString.oc_string.chars, nil);

							break;
						}

						case OCGenericType:
						case OCStrObjectType:
						case OCClassType:
						case OCModType:
							if (!GetObjcDescriptionFromObject(
								&theDummyPtr, theSymPtr, theType))
								break;

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
// ----------------------------------------------------------------------------
//	System call number is stored in r0, possible values defined in
//	<sys/syscall.h>. Call numbers are indices into a lookup table of handler
//	routines. Args being passed to the looked-up handler start at r3 or r4,
//	depending on whether it's an indirect SYS_syscall.

- (void)commentForSystemCall
{
	if (!mRegInfos[0].isValid ||
		 mRegInfos[0].value > SYS_MAXSYSCALL)
	{
		snprintf(mLineCommentCString, 11, "syscall(?)");
		return;
	}

	BOOL	isIndirect		= (mRegInfos[0].value == SYS_syscall);
	UInt32	syscallNumReg	= isIndirect ? 3 : 0;
	UInt32	syscallArg1Reg	= isIndirect ? 4 : 3;

	if (!mRegInfos[syscallNumReg].isValid	||
		mRegInfos[syscallNumReg].value > SYS_MAXSYSCALL)
	{
		snprintf(mLineCommentCString, 11, "syscall(?)");
		return;
	}

	const char*	theSysString	= gSysCalls[mRegInfos[syscallNumReg].value];

	if (!theSysString)
		return;

	char	theTempComment[50];

	theTempComment[0]	= 0;
	strncpy(theTempComment, theSysString, strlen(theSysString) + 1);

	// Handle various system calls.
	switch (mRegInfos[syscallNumReg].value)
	{
		case SYS_ptrace:
			if (mRegInfos[syscallArg1Reg].isValid &&
				mRegInfos[syscallArg1Reg].value == PT_DENY_ATTACH)
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

//	selectorForMsgSend:fromLine:
// ----------------------------------------------------------------------------

- (char*)selectorForMsgSend: (char*)outComment
				   fromLine: (Line*)inLine
{
	char*	selString	= nil;
	UInt32	theCode		= strtoul(inLine->info.code, nil, 16);

	// Bail if this is not an eligible branch.
	if (PO(theCode) != 0x12)	// b, bl, ba, bla
		return nil;

	// Bail if this is not an objc_msgSend variant.
	if (memcmp(outComment, "_objc_msgSend", 13))
		return nil;

	UInt8	sendType	= SendTypeFromMsgSend(outComment);

	// Bail for variadics.
	if (sendType == send_variadic)
		return nil;

	UInt32	selectorRegNum	=
		(sendType == sendSuper_stret || sendType == send_stret) ? 5 : 4;

	if (!mRegInfos[selectorRegNum].isValid ||
		!mRegInfos[selectorRegNum].value)
		return nil;

	// Get at the selector.
	UInt8	selType		= PointerType;
	char*	selPtr		= GetPointer(
		mRegInfos[selectorRegNum].value, &selType);

	switch (selType)
	{
		case PointerType:
			selString	= selPtr;

			break;

		case OCGenericType:
			if (selPtr)
			{
				UInt32	selPtrValue	= *(UInt32*)selPtr;

				if (mSwapped)
					selPtrValue	= OSSwapInt32(selPtrValue);

				selString	= GetPointer(selPtrValue, nil);
			}

			break;

		default:
			fprintf(stderr, "otx: [PPCProcessor commentForMsgSend]: "
				"unsupported selector type: %d\n", selType);

			break;
	}

	return selString;
}

//	commentForMsgSend:fromLine:
// ----------------------------------------------------------------------------

- (void)commentForMsgSend: (char*)ioComment
				 fromLine: (Line*)inLine
{
	char*	selString	= SelectorForMsgSend(ioComment, inLine);

	// Bail if we couldn't find the selector.
	if (!selString)
		return;

	UInt8	sendType	= SendTypeFromMsgSend(ioComment);

	// Bail on variadic calls.
	if (sendType == send_variadic)
		return;

//	UInt32	receiverRegNum		=
//		(sendType == sendSuper_stret || sendType == send_stret) ? 4 : 3;

	// Get the address of the class name string, if this a class method.
	UInt32	classNameAddy	= 0;

	// If *.classPtr is non-nil, it's not a name string.
	if (sendType == sendSuper_stret || sendType == send_stret)
	{
		if (mRegInfos[4].isValid && !mRegInfos[4].classPtr)
			classNameAddy	= mRegInfos[4].value;
	}
	else
	{
		if (mRegInfos[3].isValid && !mRegInfos[3].classPtr)
			classNameAddy	= mRegInfos[3].value;
	}

	char*	returnTypeString	=
		(sendType == sendSuper_stret || sendType == send_stret) ?
		"(struct)" : "";

	char*	className		= nil;
	char	tempComment[MAX_COMMENT_LENGTH];
//	BOOL	goodComment	= false;

	tempComment[0]	= 0;

	if (classNameAddy)
	{
		// Get at the class name
		UInt8	classNameType	= PointerType;
		char*	classNamePtr	=
			GetPointer(classNameAddy, &classNameType);

		switch (classNameType)
		{
			case PointerType:
				className	= classNamePtr;

				break;

			case OCGenericType:
				if (classNamePtr)
				{
					UInt32	namePtrValue	= *(UInt32*)classNamePtr;

					if (mSwapped)
						namePtrValue	= OSSwapInt32(namePtrValue);

					className	= GetPointer(namePtrValue, nil);
				}

				break;

			// Receiver can be a static string in these sections, but we
			// only want to display class names as receivers.
			case CFStringType:
			case ImpPtrType:
			case OCStrObjectType:
				break;

			case OCClassType:
				if (classNamePtr)
					GetObjcDescriptionFromObject(
						&className, classNamePtr, OCClassType);

			default:
				fprintf(stderr, "otx: [PPCProcessor commentForMsgSend]: "
					"unsupported class name type: %d at address: 0x%x\n",
					classNameType, inLine->info.address);

				break;
		}
	}

	if (className)
	{
//		mClassNameIsKnown	= true;
		snprintf(tempComment, MAX_COMMENT_LENGTH - 1,
			(sendType == sendSuper || sendType == sendSuper_stret) ?
			"+%s[[%s super] %s]" : "+%s[%s %s]",
			returnTypeString, className, selString);
//		goodComment	= true;
	}
	else
	{
		char*	formatString	= nil;

		switch (sendType)
		{
			case send:
			case send_rtp:
				formatString	= "-%s[r3 %s]";
				break;

			case sendSuper:
				formatString	= "-%s[[r3 super] %s]";
				break;

			case send_stret:
				formatString	= "-%s[r4 %s]";
				break;

			case sendSuper_stret:
				formatString	= "-%s[[r4 super] %s]";
				break;

			default:
				break;
		}

		snprintf(tempComment, MAX_COMMENT_LENGTH - 1, formatString,
			returnTypeString, selString);
	}
//	else
//		mClassNameIsKnown	= false;


//	if (!goodComment)
//		snprintf(tempComment, MAX_COMMENT_LENGTH - 1,
//			(sendType == sendSuper || sendType == sendSuper_stret) ?
//			"%s[[r%d super] %s]" : "%s[r%d %s]",
//			returnTypeString, receiverRegNum, selString);

	if (tempComment[0])
		strncpy(ioComment, tempComment, strlen(tempComment) + 1);
}

//	chooseLine:
// ----------------------------------------------------------------------------

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

//	selectorIsFriendly:
// ----------------------------------------------------------------------------
//	A selector is friendly if it's associated method either:
//	- returns an id of the same class that sent the message
//	- doesn't alter the 'return' register (r3 or eax)
/*
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
		(COMPARISON_FUNC_TYPE)CheckedString_Compare);

	if (friendlySel && friendlySel->length == selLength)
	{	// found a matching CRC, make sure it's not a collision.
		if (!strncmp(friendlySel->string, inSel, selLength))
			return true;
	}

	return false;
}*/

#pragma mark -
//	resetRegisters:
// ----------------------------------------------------------------------------

- (void)resetRegisters: (Line*)inLine
{
	if (!inLine)
	{
		fprintf(stderr, "otx: [PPCProcessor resetRegisters]: "
			"tried to reset with nil inLine\n");
		return;
	}

	// Setup the registers with default info. r3 is 'self' at the beginning
	// of any Obj-C method, and r12 holds the address of the 1st instruction
	// if the function was called indirectly. In the case of direct calls,
	// r12 will be overwritten before it is used, if it is used at all.
	GetObjcClassPtrFromMethod(&mCurrentClass, inLine->info.address);
	GetObjcCatPtrFromMethod(&mCurrentCat, inLine->info.address);
	memset(mRegInfos, 0, sizeof(GPRegisterInfo) * 32);

	mRegInfos[3].classPtr	= mCurrentClass;
	mRegInfos[3].catPtr		= mCurrentCat;
	mRegInfos[3].isValid	= true;
	mRegInfos[12].value		= mCurrentFuncPtr;
	mRegInfos[12].isValid	= true;
	mLR						= (GPRegisterInfo){0};
	mCTR					= (GPRegisterInfo){0};

	// Try to find out whether this is a class or instance method.
	MethodInfo*	thisMethod	= nil;

	if (GetObjcMethodFromAddress(&thisMethod, inLine->info.address))
		mIsInstanceMethod	= thisMethod->inst;

	if (mLocalSelves)
	{
		free(mLocalSelves);
		mLocalSelves	= nil;
		mNumLocalSelves	= 0;
	}

	if (mLocalVars)
	{
		free(mLocalVars);
		mLocalVars		= nil;
		mNumLocalVars	= 0;
	}

	mCurrentFuncInfoIndex++;

	if (mCurrentFuncInfoIndex >= mNumFuncInfos)
		mCurrentFuncInfoIndex	= -1;
}

//	updateRegisters:
// ----------------------------------------------------------------------------
//	Keep our local copy of the GPRs in sync as much as possible with the
//	values that the exe will use at runtime. Assign classPtr and catPtr fields
//	in a register's info if its new value points to a class or category.
// http://developer.apple.com/documentation/DeveloperTools/Conceptual/LowLevelABI/Articles/32bitPowerPC.html
// http://developer.apple.com/documentation/DeveloperTools/Conceptual/MachOTopics/Articles/dynamic_code.html

- (void)updateRegisters: (Line*)inLine;
{
	if (!inLine)
	{
		fprintf(stderr, "otx: [PPCProcessor updateRegisters]: "
			"tried to update with nil inLine\n");
		return;
	}

	UInt32	theNewValue;
	UInt32	theCode		= strtoul(
		(const char*)inLine->info.code, nil, 16);

	if (IS_BRANCH_LINK(theCode))
	{
		mLR.value	= inLine->info.address + 4;
		mLR.isValid	= true;
	}

	switch (PO(theCode))
	{
		case 0x07:	// mulli		SIMM
		{
			if (!mRegInfos[RA(theCode)].isValid)
			{
				mRegInfos[RT(theCode)]	= (GPRegisterInfo){0};
				break;
			}

			UInt64	theProduct	=
				(SInt32)mRegInfos[RA(theCode)].value * SIMM(theCode);

			mRegInfos[RT(theCode)]			= (GPRegisterInfo){0};
			mRegInfos[RT(theCode)].value	= theProduct & 0xffffffff;
			mRegInfos[RT(theCode)].isValid	= true;

			break;
		}

		case 0x08:	// subfic		SIMM
			if (!mRegInfos[RA(theCode)].isValid)
			{
				mRegInfos[RT(theCode)]	= (GPRegisterInfo){0};
				break;
			}

			theNewValue	= mRegInfos[RA(theCode)].value - SIMM(theCode);

			mRegInfos[RT(theCode)]			= (GPRegisterInfo){0};
			mRegInfos[RT(theCode)].value	= theNewValue;
			mRegInfos[RT(theCode)].isValid	= true;

			break;

		case 0x0c:	// addic		SIMM
		case 0x0d:	// addic.		SIMM
		case 0x0e:	// addi | li	SIMM
			if (RA(theCode) == 1	&&	// current reg is stack pointer (r1)
				SIMM(theCode) >= 0)		// we're accessing local vars, not args
			{
				BOOL	found	= false;
				UInt32	i;

				// Check for copied self pointer. This happens mostly in "init"
				// methods, as in: "self = [super init]"
				if (mLocalSelves)	// self was copied to a local variable
				{
					// If we're accessing a local var copy of self,
					// copy that info back to the reg in question.
					for (i = 0; i < mNumLocalSelves; i++)
					{
						if (mLocalSelves[i].offset != UIMM(theCode))
							continue;

						mRegInfos[RT(theCode)]	= mLocalSelves[i].regInfo;
						found					= true;

						break;
					}
				}

				if (found)
					break;

				// Check for other local variables.
				if (mLocalVars)
				{
					for (i = 0; i < mNumLocalVars; i++)
					{
						if (mLocalVars[i].offset != UIMM(theCode))
							continue;

						mRegInfos[RT(theCode)]	= mLocalVars[i].regInfo;
						found					= true;

						break;
					}
				}

				if (found)
					break;
			}

			// We didn't find any local variables, try immediates.
			if (RA(theCode) == 0)	// li
			{
				mRegInfos[RT(theCode)]			= (GPRegisterInfo){0};
				mRegInfos[RT(theCode)].value	= UIMM(theCode);
				mRegInfos[RT(theCode)].isValid	= true;
			}
			else					// addi
			{
				// Update rD if we know what rA is.
				if (!mRegInfos[RA(theCode)].isValid)
				{
					mRegInfos[RT(theCode)]	= (GPRegisterInfo){0};
					break;
				}

				mRegInfos[RT(theCode)].classPtr	= nil;
				mRegInfos[RT(theCode)].catPtr	= nil;

				theNewValue	= mRegInfos[RA(theCode)].value + SIMM(theCode);

				mRegInfos[RT(theCode)]			= (GPRegisterInfo){0};
				mRegInfos[RT(theCode)].value	= theNewValue;
				mRegInfos[RT(theCode)].isValid	= true;
			}

			break;

		case 0x0f:	// addis | lis
			mRegInfos[RT(theCode)].classPtr	= nil;
			mRegInfos[RT(theCode)].catPtr	= nil;

			if (RA(theCode) == 0)	// lis
			{
				mRegInfos[RT(theCode)]			= (GPRegisterInfo){0};
				mRegInfos[RT(theCode)].value	= UIMM(theCode) << 16;
				mRegInfos[RT(theCode)].isValid	= true;
				break;
			}

			// addis
			if (!mRegInfos[RA(theCode)].isValid)
			{
				mRegInfos[RT(theCode)]	= (GPRegisterInfo){0};
				break;
			}

			theNewValue	= mRegInfos[RA(theCode)].value +
				(SIMM(theCode) << 16);

			mRegInfos[RT(theCode)]			= (GPRegisterInfo){0};
			mRegInfos[RT(theCode)].value	= theNewValue;
			mRegInfos[RT(theCode)].isValid	= true;

			break;

		case 0x10:	// bcl, bcla
		case 0x13:	// bclrl, bcctrl
			if (!IS_BRANCH_LINK(theCode))	// fall thru if link
				break;

		case 0x12:	// b, ba, bl, bla
		{
			if (!LK(theCode))	// bl, bla
				break;

//			if (mReturnValueIsKnown)
//				mReturnValueIsKnown	= false;
//			else
				mRegInfos[3]	= (GPRegisterInfo){0};

			break;
		}
		case 0x15:	// rlwinm
		{
			if (!mRegInfos[RT(theCode)].isValid)
			{
				mRegInfos[RA(theCode)]	= (GPRegisterInfo){0};
				break;
			}

			UInt32	rotatedRT	=
				rotl(mRegInfos[RT(theCode)].value, RB(theCode));
			UInt32	theMask		= 0x0;
			UInt8	i;

			for (i = MB(theCode); i <= ME(theCode); i++)
				theMask	|= 1 << (31 - i);

			theNewValue	= rotatedRT & theMask;

			mRegInfos[RA(theCode)]			= (GPRegisterInfo){0};
			mRegInfos[RA(theCode)].value	= theNewValue;
			mRegInfos[RA(theCode)].isValid	= true;

			break;
		}

		case 0x18:	// ori
			if (!mRegInfos[RT(theCode)].isValid)
			{
				mRegInfos[RA(theCode)]	= (GPRegisterInfo){0};
				break;
			}

			theNewValue	=
				mRegInfos[RT(theCode)].value | (UInt32)UIMM(theCode);

			mRegInfos[RA(theCode)]			= (GPRegisterInfo){0};
			mRegInfos[RA(theCode)].value	= theNewValue;
			mRegInfos[RA(theCode)].isValid	= true;

			break;

		case 0x1f:	// multiple instructions
			switch (SO(theCode))
			{
				case 23:	// lwzx
					mRegInfos[RT(theCode)]	= (GPRegisterInfo){0};
					break;

				case 8:		// subfc
				case 40:	// subf
					if (!mRegInfos[RA(theCode)].isValid ||
						!mRegInfos[RB(theCode)].isValid)
					{
						mRegInfos[RT(theCode)]	= (GPRegisterInfo){0};
						break;
					}

					// 2's complement subtraction
					theNewValue	=
						(mRegInfos[RA(theCode)].value ^= 0xffffffff) +
						mRegInfos[RB(theCode)].value + 1;

					mRegInfos[RT(theCode)]			= (GPRegisterInfo){0};
					mRegInfos[RT(theCode)].value	= theNewValue;
					mRegInfos[RT(theCode)].isValid	= true;

					break;

				case 339:	// mfspr
					mRegInfos[RT(theCode)]	= (GPRegisterInfo){0};

					if (SPR(theCode) == LR	&&	// from LR
						mLR.isValid)
					{	// Copy LR into rD.
						mRegInfos[RT(theCode)].value	= mLR.value;
						mRegInfos[RT(theCode)].isValid	= true;
					}

					break;

				case 444:	// or | or.
					if (!mRegInfos[RT(theCode)].isValid ||
						!mRegInfos[RB(theCode)].isValid)
					{
						mRegInfos[RA(theCode)]	= (GPRegisterInfo){0};
						break;
					}

					theNewValue	=
						(mRegInfos[RT(theCode)].value |
						 mRegInfos[RB(theCode)].value);

					mRegInfos[RA(theCode)]			= (GPRegisterInfo){0};
					mRegInfos[RA(theCode)].value	= theNewValue;
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
							mCTR	= (GPRegisterInfo){0};
							break;
						}

						mCTR.value		= mRegInfos[RS(theCode)].value;
						mCTR.isValid	= true;
					}

					break;

				case 24:	// slw
					if (!mRegInfos[RS(theCode)].isValid	||
						!mRegInfos[RB(theCode)].isValid)
					{
						mRegInfos[RA(theCode)]	= (GPRegisterInfo){0};
						break;
					}

					if (SB(mRegInfos[RB(theCode)].value))
					{
						theNewValue	=
							mRegInfos[RS(theCode)].value <<
								SV(mRegInfos[RB(theCode)].value);
					}
					else	// If RB.5 == 0, RA = 0.
						theNewValue	= 0;

					mRegInfos[RA(theCode)]			= (GPRegisterInfo){0};
					mRegInfos[RA(theCode)].value	= theNewValue;
					mRegInfos[RA(theCode)].isValid	= true;

					break;

				case 536:	// srw
					if (!mRegInfos[RS(theCode)].isValid	||
						!mRegInfos[RB(theCode)].isValid)
					{
						mRegInfos[RA(theCode)]	= (GPRegisterInfo){0};
						break;
					}

					theNewValue	=
						mRegInfos[RS(theCode)].value >>
							SV(mRegInfos[RB(theCode)].value);

					mRegInfos[RA(theCode)]			= (GPRegisterInfo){0};
					mRegInfos[RA(theCode)].value	= theNewValue;
					mRegInfos[RA(theCode)].isValid	= true;

					break;

				default:
					break;
			}

			break;

		case 0x20:	// lwz
		case 0x22:	// lbz
			if (RA(theCode) == 0)
			{
				mRegInfos[RT(theCode)]			= (GPRegisterInfo){0};
				mRegInfos[RT(theCode)].value	= SIMM(theCode);
				mRegInfos[RT(theCode)].isValid	= true;
			}
			else if (mRegInfos[RA(theCode)].isValid)
			{
				UInt32	tempPtr	= (UInt32)GetPointer(
					mRegInfos[RA(theCode)].value + SIMM(theCode), nil);

				if (tempPtr)
				{
					mRegInfos[RT(theCode)].value	= *(UInt32*)tempPtr;

					if (mSwapped)
						mRegInfos[RT(theCode)].value	=
							OSSwapInt32(mRegInfos[RT(theCode)].value);

					mRegInfos[RT(theCode)].isValid	= true;
				}
				else
					mRegInfos[RT(theCode)]	= (GPRegisterInfo){0};
			}
			else if (mLocalVars)
			{
				UInt32	i;

				for (i = 0; i < mNumLocalVars; i++)
				{
					if (mLocalVars[i].offset == SIMM(theCode))
					{
						mRegInfos[RT(theCode)]	= mLocalVars[i].regInfo;
						break;
					}
				}
			}
			else
				mRegInfos[RT(theCode)]	= (GPRegisterInfo){0};

			break;

/*		case 0x22:	// lbz
			mRegInfos[RT(theCode)]	= (GPRegisterInfo){0};

			if (RA(theCode) == 0)
			{
				mRegInfos[RT(theCode)].value	= SIMM(theCode);
				mRegInfos[RT(theCode)].isValid	= true;
			}

			break;*/

		case 0x24:	// stw
			if (!mRegInfos[RT(theCode)].isValid	||
				RA(theCode) != 1				||
				SIMM(theCode) < 0)
				break;

			if (mRegInfos[RT(theCode)].classPtr)	// if it's a class
			{
				mNumLocalSelves++;

				if (mLocalSelves)
					mLocalSelves	= realloc(mLocalSelves,
						mNumLocalSelves * sizeof(VarInfo));
				else
					mLocalSelves	= malloc(sizeof(VarInfo));

				mLocalSelves[mNumLocalSelves - 1]	= (VarInfo)
					{mRegInfos[RT(theCode)], UIMM(theCode)};
			}
			else
			{
				mNumLocalVars++;

				if (mLocalVars)
					mLocalVars	= realloc(mLocalVars,
						mNumLocalVars * sizeof(VarInfo));
				else
					mLocalVars	= malloc(sizeof(VarInfo));

				mLocalVars[mNumLocalVars - 1]	= (VarInfo)
					{mRegInfos[RT(theCode)], UIMM(theCode)};
			}

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

//	restoreRegisters:
// ----------------------------------------------------------------------------

- (BOOL)restoreRegisters: (Line*)inLine
{
	if (!inLine)
	{
		fprintf(stderr, "otx: [PPCProcessor restoreRegisters]: "
			"tried to restore with nil inLine\n");
		return false;
	}

	BOOL	needNewLine	= false;

	if (mCurrentFuncInfoIndex < 0)
		return false;

	// Search current FunctionInfo for blocks that start at this address.
	FunctionInfo*	funcInfo	=
		&mFuncInfos[mCurrentFuncInfoIndex];

	if (!funcInfo->blocks)
		return false;

	UInt32	i;

	for (i = 0; i < funcInfo->numBlocks; i++)
	{
		if (funcInfo->blocks[i].address != inLine->info.address)
			continue;

		// Update machine state.
		MachineState	machState	=
			funcInfo->blocks[i].state;

		memcpy(mRegInfos, machState.regInfos,
			sizeof(GPRegisterInfo) * 32);
		mLR		= machState.regInfos[LRIndex];
		mCTR	= machState.regInfos[CTRIndex];

		if (machState.localSelves)
		{
			if (mLocalSelves)
				free(mLocalSelves);

			mNumLocalSelves	= machState.numLocalSelves;
			mLocalSelves	= malloc(
				sizeof(VarInfo) * mNumLocalSelves);
			memcpy(mLocalSelves, machState.localSelves,
				sizeof(VarInfo) * mNumLocalSelves);
		}

		if (machState.localVars)
		{
			if (mLocalVars)
				free(mLocalVars);

			mNumLocalVars	= machState.numLocalVars;
			mLocalVars		= malloc(
				sizeof(VarInfo) * mNumLocalVars);
			memcpy(mLocalVars, machState.localVars,
				sizeof(VarInfo) * mNumLocalVars);
		}

		// Optionally add a blank line before this block.
		if (mOpts.separateLogicalBlocks && inLine->chars[0]	!= '\n'	&&
			!inLine->info.isFunction)
			needNewLine	= true;

		break;
	}	// for (i = 0...)

	return needNewLine;
}

//	lineIsFunction:
// ----------------------------------------------------------------------------

- (BOOL)lineIsFunction: (Line*)inLine
{
	if (!inLine)
		return false;

	UInt32	theAddy	= inLine->info.address;

	if (theAddy == mAddrDyldStubBindingHelper	||
		theAddy == mAddrDyldFuncLookupPointer)
		return true;

	MethodInfo*	theDummyInfo	= nil;

	// In Obj-C apps, the majority of funcs will have Obj-C symbols, so check
	// those first.
	if (FindClassMethodByAddress(&theDummyInfo, theAddy))
		return true;

	if (FindCatMethodByAddress(&theDummyInfo, theAddy))
		return true;

	// If it's not an Obj-C method, maybe there's an nlist.
	if (FindSymbolByAddress(theAddy))
		return true;

	// If otool gave us a function name, but it came from a dynamic symbol...
	if (inLine->prev && !inLine->prev->info.isCode)
		return true;

	BOOL	isFunction	= false;
	UInt32	theCode		= strtoul(
		(const char*)&inLine->info.code, nil, 16);

	if ((theCode & 0xfc1fffff) == 0x7c0802a6)	// mflr to any reg
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

			if ((theCode & 0xfc0007ff) == 0x7c000008)	// trap
			{
				foundUB	= true;
				continue;
			}

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

//	codeIsBlockJump:
// ----------------------------------------------------------------------------

- (BOOL)codeIsBlockJump: (char*)inCode
{
	UInt32	theCode	= strtoul(inCode, nil, 16);

	return IS_BLOCK_BRANCH(theCode);
}

//	gatherFuncInfos
// ----------------------------------------------------------------------------

- (void)gatherFuncInfos
{
	Line*	theLine	= mPlainLineListHead;
	UInt32	theCode;

	// Loop thru lines.
	while (theLine)
	{
		if (!theLine->info.isCode)
		{
			theLine	= theLine->next;
			continue;
		}

		theCode	= strtoul(theLine->info.code, nil, 16);

		if (theLine->info.isFunction)
		{
			mCurrentFuncPtr	= theLine->info.address;
			ResetRegisters(theLine);
		}
		else
		{
			RestoreRegisters(theLine);
//			UpdateRegisters(theLine);
		}

		UpdateRegisters(theLine);

		// Check if we need to save the machine state.
		if (IS_BLOCK_BRANCH(theCode) && mCurrentFuncInfoIndex >= 0 &&
			PO(theCode) != 0x13)	// no new blocks for blr, bctr
		{
			UInt32	branchTarget;

			// Retrieve the branch target.
			if (PO(theCode) == 0x12)	// b
				branchTarget	= theLine->info.address + LI(theCode);
			else if (PO(theCode) == 0x10)	// bc
				branchTarget	= theLine->info.address + BD(theCode);

			// Retrieve current FunctionInfo.
			FunctionInfo*	funcInfo	=
				&mFuncInfos[mCurrentFuncInfoIndex];

			// 'currentBlock' will point to either an existing block which
			// we will update, or a newly allocated block.
			BlockInfo*	currentBlock	= nil;
			UInt32		i;

			if (funcInfo->blocks)
			{	// Blocks exist, find 1st one matching this address.
				// This is an exhaustive search, but the speed hit should
				// only be an issue with extremely long functions.
				for (i = 0; i < funcInfo->numBlocks; i++)
				{
					if (funcInfo->blocks[i].address == branchTarget)
					{
						currentBlock	= &funcInfo->blocks[i];
						break;
					}
				}

				if (!currentBlock)
				{
					// No matching blocks found, so allocate a new one.
					funcInfo->numBlocks++;
					funcInfo->blocks	= realloc(funcInfo->blocks,
						sizeof(BlockInfo) * funcInfo->numBlocks);
					currentBlock		=
						&funcInfo->blocks[funcInfo->numBlocks - 1];
					*currentBlock		= (BlockInfo){0};
				}
			}
			else
			{	// No existing blocks, allocate one.
				funcInfo->numBlocks++;
				funcInfo->blocks	= calloc(1, sizeof(BlockInfo));
				currentBlock		= funcInfo->blocks;
			}

			// sanity check
			if (!currentBlock)
			{
				fprintf(stderr, "otx: [PPCProcessor gatherFuncInfos] "
					"currentBlock is nil. Flame the dev.\n");
				return;
			}

			// Create a new MachineState.
			GPRegisterInfo*	savedRegs	= malloc(
				sizeof(GPRegisterInfo) * 34);

			memcpy(savedRegs, mRegInfos, sizeof(GPRegisterInfo) * 32);
			savedRegs[LRIndex]	= mLR;
			savedRegs[CTRIndex]	= mCTR;

			VarInfo*	savedSelves	= nil;

			if (mLocalSelves)
			{
				savedSelves	= malloc(
					sizeof(VarInfo) * mNumLocalSelves);
				memcpy(savedSelves, mLocalSelves,
					sizeof(VarInfo) * mNumLocalSelves);
			}

			VarInfo*	savedVars	= nil;

			if (mLocalVars)
			{
				savedVars	= malloc(
					sizeof(VarInfo) * mNumLocalVars);
				memcpy(savedVars, mLocalVars,
					sizeof(VarInfo) * mNumLocalVars);
			}

			MachineState	machState	=
				{savedRegs, savedSelves, mNumLocalSelves,
					savedVars, mNumLocalVars};

			// Store the new BlockInfo.
			BlockInfo	blockInfo	= {branchTarget, machState};

			memcpy(currentBlock, &blockInfo, sizeof(BlockInfo));
		}

		theLine	= theLine->next;
	}

	mCurrentFuncInfoIndex	= -1;
}

#ifdef OTX_DEBUG
//	printBlocks:
// ----------------------------------------------------------------------------

- (void)printBlocks: (UInt32)inFuncIndex;
{
	if (!mFuncInfos)
		return;

	FunctionInfo*	funcInfo	= &mFuncInfos[inFuncIndex];

	if (!funcInfo || !funcInfo->blocks)
		return;

	UInt32	i, j;

	fprintf(stderr, "\nfunction at 0x%x:\n\n", funcInfo->address);
	fprintf(stderr, "%d blocks\n", funcInfo->numBlocks);

	for (i = 0; i < funcInfo->numBlocks; i++)
	{
		fprintf(stderr, "\nblock %d at 0x%x:\n\n", i + 1,
			funcInfo->blocks[i].address);

		for (j = 0; j < 32; j++)
		{
			if (!funcInfo->blocks[i].state.regInfos[j].isValid)
				continue;

			fprintf(stderr, "\t\tr%d: 0x%x\n", j,
				funcInfo->blocks[i].state.regInfos[j].value);
		}
	}
}
#endif	// OTX_DEBUG

@end
