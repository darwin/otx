/*
	X86Processor.m
*/

#import <libkern/OSByteOrder.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/swap.h>
#import <objc/objc-runtime.h>
//#import <sys/ptrace.h>
#import <sys/syscall.h>

#import "X86Processor.h"
#import "SyscallStrings.h"
#import "UserDefaultKeys.h"

// ============================================================================

@implementation X86Processor

// A subclass of ExeProcessor that handles x86-specific issues.

//	initWithURL:progText:progBar:
// ————————————————————————————————————————————————————————————————————————————

- (id)initWithURL: (NSURL*)inURL
		 progText: (NSTextField*)inText
		  progBar: (NSProgressIndicator*)inProg
{
	if ((self = [super initWithURL: inURL
		progText: inText progBar: inProg]) == nil)
		return nil;

	strncpy(mArchString, "i386", 5);

	mArchSelector				= CPU_TYPE_I386;
	mFieldWidths.offset			= 8;
	mFieldWidths.address		= 10;
	mFieldWidths.instruction	= 22;
	mFieldWidths.mnemonic		= 12;
	mFieldWidths.operands		= 29;

	return self;
}

//	loadDyldDataSection:
// ————————————————————————————————————————————————————————————————————————————

- (void)loadDyldDataSection: (section*)inSect
{
	[super loadDyldDataSection: inSect];

	if (!mAddrDyldStubBindingHelper)
		return;

	mAddrDyldFuncLookupPointer	= mAddrDyldStubBindingHelper + 12;
}

//	codeFromLine:
// ————————————————————————————————————————————————————————————————————————————

- (void)codeFromLine: (Line*)inLine
{
	UInt8	theInstLength	= 0;
	UInt32	thisAddy		= inLine->info.address;
	Line*	nextLine		= inLine->next;

	// Try to find next code line.
	while (nextLine)
	{
		if (![self lineIsCode: nextLine->chars])
			nextLine	= nextLine->next;
		else
			break;
	}

	// This instruction size is either the difference of 2 addys or the
	// difference of this addy from the end of the section.
	UInt32	nextAddy	= mEndOfText;

	if (nextLine)
	{
		UInt32	newNextAddy	= AddressFromLine(nextLine->chars);

		if (newNextAddy > thisAddy && newNextAddy <= thisAddy + 12)
			nextAddy	= newNextAddy;
	}

	theInstLength	= nextAddy - thisAddy;

	// Fetch the instruction.
	unsigned char	charData[14]		= {0};
	char			formatString[50]	= {0};
	char*			theMachPtr			= (char*)mMachHeader;
	char*			byteFormat			= "%02x";
	UInt8			byteFormatLength	= strlen(byteFormat);
	UInt8			formatMarker		= 0;
	UInt8			i;

	for (i = 0; i < theInstLength; i++)
	{
		charData[i]	= *(unsigned char*)
			(theMachPtr + (thisAddy - mTextOffset) + i);
		memcpy(&formatString[formatMarker], byteFormat, byteFormatLength);
		formatMarker	+= byteFormatLength;
	}

	snprintf(inLine->info.code, 25, formatString,
		charData[0], charData[1], charData[2], charData[3], charData[4],
		charData[5], charData[6], charData[7], charData[8], charData[9],
		charData[10], charData[11], charData[12], charData[13]);
}

//	checkThunk:
// ————————————————————————————————————————————————————————————————————————————

- (void)checkThunk: (Line*)inLine
{
	if (!inLine || !inLine->prev || inLine->info.code[2])
		return;

	if (inLine->info.code[0] != 'c' ||
		inLine->info.code[1] != '3')
		return;

	UInt32		theInstruction	= strtoul(inLine->prev->info.code, nil, 16);
	ThunkInfo	theThunk		= {inLine->prev->info.address, NOREG};

	switch (theInstruction)
	{
		case 0x8b0424:	// movl	(%esp,1), %eax
			theThunk.reg	= EAX;
			break;

		case 0x8b0c24:	// movl	(%esp,1), %ecx
			theThunk.reg	= ECX;
			break;

		case 0x8b1424:	// movl	(%esp,1), %edx
			theThunk.reg	= EDX;
			break;

		case 0x8b1c24:	// movl	(%esp,1), %ebx
			theThunk.reg	= EBX;
			break;

		default:
			return;
	}

	// Store a thunk.
	mNumThunks++;

	if (mThunks)
		mThunks	= realloc(mThunks,
			mNumThunks * sizeof(ThunkInfo));
	else
		mThunks	= malloc(sizeof(ThunkInfo));

	mThunks[mNumThunks - 1]	= theThunk;

	// Recognize it as a function.
	inLine->prev->info.isFunction	= true;

	if (inLine->prev->alt)
		inLine->prev->alt->info.isFunction	= true;
}

//	commentForLine:
// ————————————————————————————————————————————————————————————————————————————

- (void)commentForLine: (Line*)inLine;
{
	char*	theDummyPtr	= nil;
	char*	theSymPtr	= nil;
	UInt32	localAddy	= 0;
	UInt8	modRM		= 0;
	UInt8	opcode;

	sscanf(inLine->info.code, "%02hhx", &opcode);
	bzero(mLineCommentCString, MAX_COMMENT_LENGTH);

	switch (opcode)
	{
		case 0x0f:	// 2-byte and SSE opcodes	**add sysenter support here
		{
			if (inLine->info.code[2] != '2' ||
				inLine->info.code[3] != 'e')	// ucomiss
				break;

			// sscanf interprets source values as big-endian, regardless of
			// host architecture. If source value is little-endian, as in x86
			// instructions, we must always swap.
			sscanf(&inLine->info.code[6], "%08x", &localAddy);
			localAddy	= OSSwapInt32(localAddy);

			theDummyPtr	= GetPointer(localAddy, nil);

			if (theDummyPtr)
			{
				UInt32	theInt32	= *(UInt32*)theDummyPtr;

				if (mSwapped)
					theInt32	= OSSwapInt32(theInt32);

				snprintf(mLineCommentCString, 30, "%G", *(float*)&theInt32);
			}

			break;
		}

		case 0x3c:	// cmpb	imm8,al
		{
			UInt8	imm;

			sscanf(&inLine->info.code[2], "%02hhx", &imm);

			// Check for a single printable 7-bit char.
			if (imm >= 0x20 && imm < 0x7f)
				snprintf(mLineCommentCString, 4, "'%c'", imm);

			break;
		}

		case 0x66:
			if (inLine->info.code[2] != '0' ||
				inLine->info.code[3] != 'f' ||
				inLine->info.code[4] != '2' ||
				inLine->info.code[5] != 'e')	// ucomisd
				break;

			sscanf(&inLine->info.code[8], "%08x", &localAddy);
			localAddy	= OSSwapInt32(localAddy);

			theDummyPtr	= GetPointer(localAddy, nil);

			if (theDummyPtr)
			{
				UInt64	theInt64	= *(UInt64*)theDummyPtr;

				if (mSwapped)
					theInt64	= OSSwapInt64(theInt64);

				snprintf(mLineCommentCString, 30, "%lG", *(double*)&theInt64);
			}

			break;

		// immediate group 1 - add, sub, cmp etc
		case 0x80:	// imm8,r8
		case 0x83:	// imm8,r32
		{
			sscanf(&inLine->info.code[2], "%02hhx", &modRM);

			// In immediate group 1 we only want cmpb
			if (OPEXT(modRM) != 7)
				break;

			UInt8	imm;
			UInt8	immOffset	= 4;

			if (HAS_DISP8(modRM))
				immOffset	+=	2;

			sscanf(&inLine->info.code[immOffset], "%02hhx", &imm);

			// Check for a single printable 7-bit char.
			if (imm >= 0x20 && imm < 0x7f)
				snprintf(mLineCommentCString, 4, "'%c'", imm);

			break;
		}

		case 0x2b:	// subl	r/m32,r32
		case 0x81:	// immediate group 1 - imm32,r32
		case 0x88:	// movb	r8,r/m8
		case 0x89:	// movl	r32,r/m32
		case 0x8b:	// movl	r/m32,r32
			sscanf(&inLine->info.code[2], "%02hhx", &modRM);

			// In immediate group 1 we only want cmpl
			if (opcode == 0x81 && OPEXT(modRM) != 7)
				break;

			if (MOD(modRM) == MODimm)	// 1st addressing mode
			{
				if (RM(modRM) == DISP32)
				{
					sscanf(&inLine->info.code[4], "%08x", &localAddy);
					localAddy	= OSSwapInt32(localAddy);
				}
				else
				if (mRegInfos[REG1(modRM)].isValid	&&
					mRegInfos[REG1(modRM)].classPtr	&&
					REG2(modRM) == ESP)
				{
					objc_class*	ocClass		= mRegInfos[REG1(modRM)].classPtr;
					char*		className	= GetPointer((ocClass->name) ?
						(UInt32)ocClass->name : (UInt32)ocClass->isa, nil);

					if (className)
						strncpy(mLineCommentCString, className,
							strlen(className) + 1);
				}
			}
			else
			{
				if (mRegInfos[REG2(modRM)].classPtr)	// address relative to class
				{
					if (!mRegInfos[REG2(modRM)].isValid)
						break;

					// Ignore the 4th addressing mode
					if (MOD(modRM) == MODx)
						break;

					objc_ivar	theIvar	= {0};

					if (MOD(modRM) == MOD8)
					{
						UInt8	theSymOffset;

						sscanf(&inLine->info.code[4], "%02hhx", &theSymOffset);

						if (!FindIvar(&theIvar,
							mRegInfos[REG2(modRM)].classPtr, theSymOffset))
							break;
					}
					else if (MOD(modRM) == MOD32)
					{
						UInt32	theSymOffset;

						sscanf(&inLine->info.code[4], "%08x", &theSymOffset);
						theSymOffset	= OSSwapInt32(theSymOffset);

						if (!FindIvar(&theIvar,
							mRegInfos[REG2(modRM)].classPtr, theSymOffset))
							break;
					}

					theSymPtr	= GetPointer(
						(UInt32)theIvar.ivar_name, nil);

					if (theSymPtr)
					{
						if (mShowIvarTypes)
						{
							char	theTypeCString[MAX_TYPE_STRING_LENGTH]	= {0};

							GetDescription(theTypeCString,
								GetPointer((UInt32)theIvar.ivar_type, nil));
							snprintf(mLineCommentCString,
								MAX_COMMENT_LENGTH - 1, "(%s)%s",
								theTypeCString, theSymPtr);
						}
						else
							snprintf(mLineCommentCString,
								MAX_COMMENT_LENGTH - 1, "%s",
								theSymPtr);
					}
				}
				else if (MOD(modRM) == MOD32)	// absolute address
				{
					if (HAS_SIB(modRM))
						break;

					if (REG2(modRM) == mCurrentThunk &&
						mRegInfos[mCurrentThunk].isValid)
					{
						UInt32	imm;

						sscanf(&inLine->info.code[4], "%08x", &imm);
						imm	= OSSwapInt32(imm);

						localAddy	=
							mRegInfos[mCurrentThunk].intValue + imm;
					}
					else
					{
						sscanf(&inLine->info.code[4], "%08x", &localAddy);
						localAddy	= OSSwapInt32(localAddy);
					}
				}
			}

			break;

		case 0x8d:	// leal
			sscanf(&inLine->info.code[2], "%02hhx", &modRM);

			if (mRegInfos[REG2(modRM)].classPtr)	// address relative to class
			{
				if (!mRegInfos[REG2(modRM)].isValid)
					break;

				// Ignore the 1st and 4th addressing modes
				if (MOD(modRM) == MODimm || MOD(modRM) == MODx)
					break;

				objc_ivar	theIvar	= {0};

				if (MOD(modRM) == MOD8)
				{
					UInt8	theSymOffset;

					sscanf(&inLine->info.code[4], "%02hhx", &theSymOffset);

					if (!FindIvar(&theIvar, mRegInfos[REG2(modRM)].classPtr,
						theSymOffset))
						break;
				}
				else if (MOD(modRM) == MOD32)
				{
					UInt32	theSymOffset;

					sscanf(&inLine->info.code[4], "%08x", &theSymOffset);
					theSymOffset	= OSSwapInt32(theSymOffset);

					if (!FindIvar(&theIvar, mRegInfos[REG2(modRM)].classPtr,
						theSymOffset))
						break;
				}

				theSymPtr	= GetPointer(
					(UInt32)theIvar.ivar_name, nil);

				if (theSymPtr)
				{
					if (mShowIvarTypes)
					{
						char	theTypeCString[MAX_TYPE_STRING_LENGTH]	= {0};

						GetDescription(theTypeCString,
							GetPointer((UInt32)theIvar.ivar_type, nil));
						snprintf(mLineCommentCString,
							MAX_COMMENT_LENGTH - 1, "(%s)%s",
							theTypeCString, theSymPtr);
					}
					else
						snprintf(mLineCommentCString,
							MAX_COMMENT_LENGTH - 1, "%s",
							theSymPtr);
				}
			}
			else if (REG2(modRM) == mCurrentThunk)
			{
				UInt32	imm;

				sscanf(&inLine->info.code[4], "%08x", &imm);
				imm	= OSSwapInt32(imm);

				localAddy	= mRegInfos[mCurrentThunk].intValue + imm;
			}
			else
			{
				sscanf(&inLine->info.code[4], "%08x", &localAddy);
				localAddy	= OSSwapInt32(localAddy);
			}

			break;

		case 0xa1:	// movl	moffs32,r32
		case 0xa3:	// movl	r32,moffs32
			sscanf(&inLine->info.code[2], "%08x", &localAddy);
			localAddy	= OSSwapInt32(localAddy);

			break;

		case 0xb0:	// movb imm8,%al
		case 0xb1:	// movb imm8,%cl
		case 0xb2:	// movb imm8,%dl
		case 0xb3:	// movb imm8,%bl
		case 0xb4:	// movb imm8,%ah
		case 0xb5:	// movb imm8,%ch
		case 0xb6:	// movb imm8,%dh
		case 0xb7:	// movb imm8,%bh
		{
			UInt8	imm;

			sscanf(&inLine->info.code[2], "%02hhx", &imm);

			// Check for a single printable 7-bit char.
			if (imm >= 0x20 && imm < 0x7f)
				snprintf(mLineCommentCString, 4, "'%c'", imm);

			break;
		}

		case 0xb8:	// movl	imm32,%eax
		case 0xb9:	// movl	imm32,%ecx
		case 0xba:	// movl	imm32,%edx
		case 0xbb:	// movl	imm32,%ebx
		case 0xbc:	// movl	imm32,%esp
		case 0xbd:	// movl	imm32,%ebp
		case 0xbe:	// movl	imm32,%esi
		case 0xbf:	// movl	imm32,%edi
			sscanf(&inLine->info.code[2], "%08x", &localAddy);
			localAddy	= OSSwapInt32(localAddy);

			// Check for a four char code.
			if (localAddy >= 0x20202020 && localAddy < 0x7f7f7f7f)
			{
				char*	fcc	= (char*)&localAddy;

				if (fcc[0] >= 0x20 && fcc[0] < 0x7f &&
					fcc[1] >= 0x20 && fcc[1] < 0x7f &&
					fcc[2] >= 0x20 && fcc[2] < 0x7f &&
					fcc[3] >= 0x20 && fcc[3] < 0x7f)
				{
					if (!mSwapped)
						localAddy	= OSSwapInt32(localAddy);

					snprintf(mLineCommentCString,
						7, "'%.4s'", fcc);
				}
			}
			else	// Check for a single printable 7-bit char.
			if (localAddy >= 0x20 && localAddy < 0x7f)
			{
				snprintf(mLineCommentCString, 4, "'%c'", localAddy);
			}

			break;

		case 0xc7:	// movl	imm32,r/m32
		{
			sscanf(&inLine->info.code[2], "%02hhx", &modRM);

			if (mRegInfos[REG2(modRM)].classPtr)	// address relative to class
			{
				if (!mRegInfos[REG2(modRM)].isValid)
					break;

				// Ignore the 1st and 4th addressing modes
				if (MOD(modRM) == MODimm || MOD(modRM) == MODx)
					break;

				UInt8	immOffset						= 4;
				char	fcc[7]							= {0};
				char	tempComment[MAX_COMMENT_LENGTH]	= {0};

				if (HAS_DISP8(modRM))
					immOffset	+= 2;
				else if (HAS_DISP32(modRM))
					immOffset	+= 8;

				if (HAS_SIB(modRM))
					immOffset	+= 2;

				objc_ivar	theIvar	= {0};

				if (MOD(modRM) == MOD8)
				{
					UInt8	theSymOffset;

					// offset precedes immediate value, subtract
					// sizeof(UInt8) * 2
					sscanf(&inLine->info.code[immOffset - 2], "%02hhx", &theSymOffset);

					if (!FindIvar(&theIvar, mRegInfos[REG2(modRM)].classPtr,
						theSymOffset))
						break;
				}
				else if (MOD(modRM) == MOD32)
				{
					UInt32	imm;
					UInt32	theSymOffset;

					sscanf(&inLine->info.code[immOffset], "%08x", &imm);
					imm	= OSSwapInt32(imm);

					// offset precedes immediate value, subtract
					// sizeof(UInt32) * 2
					sscanf(&inLine->info.code[immOffset - 8], "%08x", &theSymOffset);
					theSymOffset	= OSSwapInt32(theSymOffset);

					// Check for a four char code.
					if (imm >= 0x20202020 && imm < 0x7f7f7f7f)
					{
						char*	tempFCC	= (char*)&imm;

						if (tempFCC[0] >= 0x20 && tempFCC[0] < 0x7f &&
							tempFCC[1] >= 0x20 && tempFCC[1] < 0x7f &&
							tempFCC[2] >= 0x20 && tempFCC[2] < 0x7f &&
							tempFCC[3] >= 0x20 && tempFCC[3] < 0x7f)
						{
							if (!mSwapped)
								imm	= OSSwapInt32(imm);

							snprintf(fcc, 7, "'%.4s'", tempFCC);
						}
					}
					else	// Check for a single printable 7-bit char.
					if (imm >= 0x20 && imm < 0x7f)
					{
						snprintf(fcc, 4, "'%c'", imm);
					}

					FindIvar(&theIvar, mRegInfos[REG2(modRM)].classPtr,
						theSymOffset);
				}

				theSymPtr	= GetPointer(
					(UInt32)theIvar.ivar_name, nil);

				// copy four char code and/or var name to comment.
				if (fcc[0])
					strncpy(tempComment, fcc, strlen(fcc) + 1);

				if (theSymPtr)
				{
					if (fcc[0])
						strncat(tempComment, " ", 2);

					UInt32	tempCommentLength	= strlen(tempComment);

					if (mShowIvarTypes)
					{
						char	theTypeCString[MAX_TYPE_STRING_LENGTH]	= {0};

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
					strncpy(mLineCommentCString, tempComment,
						MAX_COMMENT_LENGTH - 1);
			}
			else	// absolute address
			{
				UInt8	immOffset = 4;

				if (HAS_DISP8(modRM))
					immOffset	+= 2;

				if (HAS_SIB(modRM))
					immOffset	+= 2;

				sscanf(&inLine->info.code[immOffset], "%08x", &localAddy);
				localAddy	= OSSwapInt32(localAddy);

				// Check for a four char code.
				if (localAddy >= 0x20202020 && localAddy < 0x7f7f7f7f)
				{
					char*	fcc	= (char*)&localAddy;

					if (fcc[0] >= 0x20 && fcc[0] < 0x7f &&
						fcc[1] >= 0x20 && fcc[1] < 0x7f &&
						fcc[2] >= 0x20 && fcc[2] < 0x7f &&
						fcc[3] >= 0x20 && fcc[3] < 0x7f)
					{
						if (!mSwapped)
							localAddy	= OSSwapInt32(localAddy);

						snprintf(mLineCommentCString,
							7, "'%.4s'", fcc);
					}
				}
				else	// Check for a single printable 7-bit char.
				if (localAddy >= 0x20 && localAddy < 0x7f)
				{
					snprintf(mLineCommentCString, 4, "'%c'", localAddy);
				}
			}

			break;
		}

		case 0xcd:	// int
			sscanf(&inLine->info.code[2], "%02hhx", &modRM);

			if (modRM == 0x80)
				CommentForSystemCall();

			break;

		case 0xd9:	// fldsl	r/m32
		case 0xdd:	// fldll	
			sscanf(&inLine->info.code[2], "%02hhx", &modRM);

			if (mRegInfos[REG2(modRM)].classPtr)	// address relative to class
			{
				if (!mRegInfos[REG2(modRM)].isValid)
					break;

				// Ignore the 1st and 4th addressing modes
				if (MOD(modRM) == MODimm || MOD(modRM) == MODx)
					break;

				objc_ivar	theIvar	= {0};

				if (MOD(modRM) == MOD8)
				{
					UInt8	theSymOffset;

					sscanf(&inLine->info.code[4], "%02hhx", &theSymOffset);

					if (!FindIvar(&theIvar, mRegInfos[REG2(modRM)].classPtr,
						theSymOffset))
						break;
				}
				else if (MOD(modRM) == MOD32)
				{
					UInt32	theSymOffset;

					sscanf(&inLine->info.code[4], "%08x", &theSymOffset);
					theSymOffset	= OSSwapInt32(theSymOffset);

					if (!FindIvar(&theIvar, mRegInfos[REG2(modRM)].classPtr,
						theSymOffset))
						break;
				}

				theSymPtr	= GetPointer(
					(UInt32)theIvar.ivar_name, nil);

				if (theSymPtr)
				{
					if (mShowIvarTypes)
					{
						char	theTypeCString[MAX_TYPE_STRING_LENGTH]	= {0};

						GetDescription(theTypeCString,
							GetPointer((UInt32)theIvar.ivar_type, nil));
						snprintf(mLineCommentCString,
							MAX_COMMENT_LENGTH - 1, "(%s)%s",
							theTypeCString, theSymPtr);
					}
					else
						snprintf(mLineCommentCString,
							MAX_COMMENT_LENGTH - 1, "%s",
							theSymPtr);
				}
			}
			else	// absolute address
			{
				UInt8	immOffset = 4;

				if (HAS_DISP8(modRM))
					immOffset	+= 2;

				if (HAS_SIB(modRM))
					immOffset	+= 2;

				sscanf(&inLine->info.code[immOffset], "%08x", &localAddy);
				localAddy	= OSSwapInt32(localAddy);

				theDummyPtr	= GetPointer(localAddy, nil);

				if (!theDummyPtr)
					break;

				if (LO(opcode) == 0x9)	// fldsl
				{
					UInt32	theInt32	= *(UInt32*)theDummyPtr;

					if (mSwapped)
						theInt32	= OSSwapInt32(theInt32);

					// dance around printf's type coersion
					snprintf(mLineCommentCString,
						30, "%G", *(float*)&theInt32);
				}
				else if (LO(opcode) == 0xd)	// fldll
				{
					UInt64	theInt64	= *(UInt64*)theDummyPtr;

					if (mSwapped)
						theInt64	= OSSwapInt64(theInt64);

					// dance around printf's type coersion
					snprintf(mLineCommentCString,
						30, "%lG", *(double*)&theInt64);
				}
			}

			break;

		case 0xf2:	// repne/repnz or movsd, mulsd etc
		case 0xf3:	// rep/repe or movss, mulss etc
		{
			UInt8	byte2;

			sscanf(&inLine->info.code[2], "%02hhx", &byte2);

			if (byte2 != 0x0f)	// movsd/s, divsd/s, addsd/s etc
				break;

			sscanf(&inLine->info.code[6], "%02hhx", &modRM);

			if (mRegInfos[REG2(modRM)].classPtr)	// address relative to self
			{
				if (!mRegInfos[REG2(modRM)].isValid)
					break;

				// Ignore the 1st and 4th addressing modes
				if (MOD(modRM) == MODimm || MOD(modRM) == MODx)
					break;

				objc_ivar	theIvar	= {0};

				if (MOD(modRM) == MOD8)
				{
					UInt8	theSymOffset;

					sscanf(&inLine->info.code[8], "%02hhx", &theSymOffset);

					if (!FindIvar(&theIvar, mRegInfos[REG2(modRM)].classPtr,
						theSymOffset))
						break;
				}
				else if (MOD(modRM) == MOD32)
				{
					UInt32	theSymOffset;

					sscanf(&inLine->info.code[8], "%08x", &theSymOffset);
					theSymOffset	= OSSwapInt32(theSymOffset);

					if (!FindIvar(&theIvar, mRegInfos[REG2(modRM)].classPtr,
						theSymOffset))
						break;
				}

				theSymPtr	= GetPointer(
					(UInt32)theIvar.ivar_name, nil);

				if (theSymPtr)
				{
					if (mShowIvarTypes)
					{
						char	theTypeCString[MAX_TYPE_STRING_LENGTH]	= {0};

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
				sscanf(&inLine->info.code[8], "%08x", &localAddy);
				localAddy	= OSSwapInt32(localAddy);

				theDummyPtr	= GetPointer(localAddy, nil);

				if (theDummyPtr)
				{
					if (LO(opcode) == 0x3)
					{
						UInt32	theInt32	= *(UInt32*)theDummyPtr;

						if (mSwapped)
							theInt32	= OSSwapInt32(theInt32);

						snprintf(mLineCommentCString,
							30, "%G", *(float*)&theInt32);
					}
					else if (LO(opcode) == 0x2)
					{
						UInt64	theInt64	= *(UInt64*)theDummyPtr;

						if (mSwapped)
							theInt64	= OSSwapInt64(theInt64);

						snprintf(mLineCommentCString,
							30, "%lG", *(double*)&theInt64);
					}
				}
			}

			break;
		}

		default:
			break;
	}	// switch (opcode)

	if (!mLineCommentCString[0])
	{
		UInt8	theType		= PointerType;
		UInt32	theValue;

		theDummyPtr	= GetPointer(localAddy, &theType);

		if (theDummyPtr)
		{
			switch (theType)
			{
				case DataGenericType:
					theValue	= *(UInt32*)theDummyPtr;

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

				case PointerType:
					theSymPtr	= theDummyPtr;

					break;

				case CFStringType:
				{
					cf_string_object	theCFString	= 
						*(cf_string_object*)theDummyPtr;

					if (theCFString.oc_string.length == 0)
					{
						theSymPtr	= nil;
						break;
					}

					theValue	= (UInt32)theCFString.oc_string.chars;

					if (mSwapped)
						theValue	= OSSwapInt32(theValue);

					theSymPtr	= GetPointer(theValue, nil);

					break;
				}
				case ImpPtrType:
				case NLSymType:
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

					theValue	= (UInt32)theCFString.oc_string.chars;

					if (mSwapped)
						theValue	= OSSwapInt32(theValue);

					theSymPtr	= GetPointer( theValue, nil);

					break;
				}

				case OCGenericType:
				case OCStrObjectType:
				case OCClassType:
				case OCModType:
					theSymPtr	= [self objcDescriptionFromObject:
						theDummyPtr type: theType];

					break;

				default:
					break;
			}
		}

		if (theSymPtr)
		{
			if (theType == PStringType)
				snprintf(mLineCommentCString, 255,
					"%*s", theSymPtr[0], theSymPtr + 1);
			else
				snprintf(mLineCommentCString,
					MAX_COMMENT_LENGTH - 1, "%s", theSymPtr);
		}
	}
}

//	commentForSystemCall
// ————————————————————————————————————————————————————————————————————————————
//	System call number is stored in EAX, possible values defined in
//	<sys/syscall.h>. Call numbers are indices into a lookup table of handler
//	routines. Args being passed to the looked-up handler are on the stack.

- (void)commentForSystemCall
{
	if (!mRegInfos[EAX].isValid ||
		 mRegInfos[EAX].intValue > SYS_MAXSYSCALL)
		return;

	const char*	theSysString	= gSysCalls[mRegInfos[EAX].intValue];

	if (!theSysString)
		return;

	strncpy(mLineCommentCString, theSysString, strlen(theSysString) + 1);

	// Handle various system calls.
	// If this was Linux, args would be passed in registers and we could
	// easily spot PT_DENY_ATTACH. In Mach/BSD, we'd have to keep track of
	// the stack...
}

//	chooseLine:
// ————————————————————————————————————————————————————————————————————————————

- (void)chooseLine: (Line**)ioLine
{
	if (!(*ioLine) || !(*ioLine)->info.isCode || !(*ioLine)->alt)
		return;

	UInt8	theCode;

	sscanf((*ioLine)->info.code, "%02hhx", &theCode);

	if ((theCode == 0xe8 || theCode == 0xff || theCode == 0x9a) &&
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

//	postProcessCodeLine:
// ————————————————————————————————————————————————————————————————————————————

- (void)postProcessCodeLine: (Line**)ioLine;
{
	if ((*ioLine)->info.code[0] != 'e'	||	// calll
		(*ioLine)->info.code[1] != '8'	||
		!(*ioLine)->next				||
		!mLineOperandsCString[0])
		return;

	char*	theSubstring	=
		strstr(mLineOperandsCString, "i686.get_pc_thunk.");

	if (theSubstring)	// otool knew this was a thunk call
	{
		BOOL	applyThunk	= false;

		if (!strncmp(&theSubstring[18], "ax", 2))
		{
			mCurrentThunk	= EAX;
			applyThunk		= true;
		}
		else if (!strncmp(&theSubstring[18], "bx", 2))
		{
			mCurrentThunk	= EBX;
			applyThunk		= true;
		}
		else if (!strncmp(&theSubstring[18], "cx", 2))
		{
			mCurrentThunk	= ECX;
			applyThunk		= true;
		}
		else if (!strncmp(&theSubstring[18], "dx", 2))
		{
			mCurrentThunk	= EDX;
			applyThunk		= true;
		}

		if (applyThunk)
		{
			mRegInfos[mCurrentThunk].intValue	=
				(*ioLine)->next->info.address;
			mRegInfos[mCurrentThunk].isValid	= true;
		}
	}
	else	// otool didn't spot it, maybe we did earlier...
	{
		if (!mThunks)
			return;

		UInt32	i, target;
		BOOL	found	= false;

		for (i = 0; i < mNumThunks && !found; i++)
		{
			target	= strtoul(mLineOperandsCString, nil, 16);

			if (target == mThunks[i].address)
			{
				found			= true;
				mCurrentThunk	= mThunks[i].reg;

				mRegInfos[mCurrentThunk].intValue	=
					(*ioLine)->next->info.address;
				mRegInfos[mCurrentThunk].isValid	= true;
			}
		}
	}
}

//	updateRegisters:
// ————————————————————————————————————————————————————————————————————————————

- (void)updateRegisters: (Line*)inLine;
{
	if (!inLine)
	{
		bzero(&mRegInfos[0], sizeof(RegisterInfo) * 8);
		mCurrentThunk	= NOREG;

		if (mLocalSelves)
		{
			free(mLocalSelves);
			mLocalSelves	= nil;
			mNumLocalSelves	= 0;
		}

		return;
	}

	UInt8	opcode;
	UInt8	modRM;

	sscanf(inLine->info.code, "%02hhx", &opcode);

	switch (opcode)
	{
		// immediate group 1
		// add, or, adc, sbb, and, sub, xor, cmp
		case 0x83:	// EXTS(imm8),r32
		{
			sscanf(&inLine->info.code[2], "%02hhx", &modRM);

			if (!mRegInfos[REG1(modRM)].isValid)
				break;

			UInt8	imm;

			sscanf(&inLine->info.code[4], "%02hhx", &imm);

			switch (OPEXT(modRM))
			{
				case 0:	// add
					mRegInfos[REG1(modRM)].intValue	+= (SInt32)imm;
					mRegInfos[REG1(modRM)].classPtr	= nil;
					mRegInfos[REG1(modRM)].catPtr	= nil;

					break;

				case 1:	// or
					mRegInfos[REG1(modRM)].intValue	|= (SInt32)imm;
					mRegInfos[REG1(modRM)].classPtr	= nil;
					mRegInfos[REG1(modRM)].catPtr	= nil;

					break;

				case 4:	// and
					mRegInfos[REG1(modRM)].intValue	&= (SInt32)imm;
					mRegInfos[REG1(modRM)].classPtr	= nil;
					mRegInfos[REG1(modRM)].catPtr	= nil;

					break;

				case 5:	// sub
					mRegInfos[REG1(modRM)].intValue	-= (SInt32)imm;
					mRegInfos[REG1(modRM)].classPtr	= nil;
					mRegInfos[REG1(modRM)].catPtr	= nil;

					break;

				case 6:	// xor
					mRegInfos[REG1(modRM)].intValue	^= (SInt32)imm;
					mRegInfos[REG1(modRM)].classPtr	= nil;
					mRegInfos[REG1(modRM)].catPtr	= nil;

					break;

				default:
					break;
			}	// switch (OPEXT(modRM))

			break;
		}

		case 0x89:	// mov reg to mem
		{
			sscanf(&inLine->info.code[2], "%02hhx", &modRM);

			if (!mRegInfos[REG1(modRM)].isValid		||
				!mRegInfos[REG1(modRM)].classPtr	||
				REG2(modRM) != EBP)
				break;

			if (MOD(modRM) == MOD8)
			{
				SInt8	offset;

				sscanf(&inLine->info.code[4], "%02hhx", &offset);

				if (offset >= 0)
					break;

				// Copying self from a register to a local var.
				mNumLocalSelves++;

				if (mLocalSelves)
					mLocalSelves	= realloc(mLocalSelves,
						mNumLocalSelves * sizeof(VarInfo));
				else
					mLocalSelves	= malloc(sizeof(VarInfo));

				mLocalSelves[mNumLocalSelves - 1]	= (VarInfo)
					{mRegInfos[REG1(modRM)], offset};
			}

			break;
		}

		case 0x8b:	// mov mem to reg
			sscanf(&inLine->info.code[2], "%02hhx", &modRM);

			bzero(&mRegInfos[REG1(modRM)], sizeof(RegisterInfo));

			if (MOD(modRM) == MOD8)
			{
				SInt8	offset;

				sscanf(&inLine->info.code[4], "%02hhx", &offset);

				if (REG2(modRM) == EBP && offset == 0x8)
				{	// Copying self from 1st arg to a register.
					mRegInfos[REG1(modRM)].classPtr	= mCurrentClass;
					mRegInfos[REG1(modRM)].catPtr	= mCurrentCat;
					mRegInfos[REG1(modRM)].isValid	= true;
				}
				else
				{	// Check for copied self pointer.
					if (mLocalSelves		&&
						REG2(modRM) == EBP	&&
						offset < 0)
					{
						UInt32	i;

						for (i = 0; i < mNumLocalSelves; i++)
						{
							if (mLocalSelves[i].offset != offset)
								continue;

							// If we're accessing a local var copy of self,
							// copy that info back to the reg in question.
							bzero(&mRegInfos[REG1(modRM)], sizeof(RegisterInfo));
							mRegInfos[REG1(modRM)]	= mLocalSelves[i].regInfo;

							// and split.
							break;
						}
					}
				}
			}

			break;

		case 0xb0:	// movb imm8,%al
		case 0xb1:	// movb imm8,%cl
		case 0xb2:	// movb imm8,%dl
		case 0xb3:	// movb imm8,%bl
		case 0xb4:	// movb imm8,%ah
		case 0xb5:	// movb imm8,%ch
		case 0xb6:	// movb imm8,%dh
		case 0xb7:	// movb imm8,%bh
		{
			UInt8	imm;

			bzero(&mRegInfos[REG2(opcode)], sizeof(RegisterInfo));

			sscanf(&inLine->info.code[2], "%02hhx", &imm);
			mRegInfos[REG2(opcode)].intValue	= imm;
			mRegInfos[REG2(opcode)].isValid		= true;

			break;
		}

		case 0xa1:	// movl	moffs32,%eax
			bzero(&mRegInfos[EAX], sizeof(RegisterInfo));

			sscanf(&inLine->info.code[2], "%08x", &mRegInfos[EAX].intValue);
			mRegInfos[EAX].intValue	= OSSwapInt32(mRegInfos[EAX].intValue);
			mRegInfos[EAX].isValid	= true;

			break;
		case 0xb8:	// movl	imm32,%eax
		case 0xb9:	// movl	imm32,%ecx
		case 0xba:	// movl	imm32,%edx
		case 0xbb:	// movl	imm32,%ebx
		case 0xbc:	// movl	imm32,%esp
		case 0xbd:	// movl	imm32,%ebp
		case 0xbe:	// movl	imm32,%esi
		case 0xbf:	// movl	imm32,%edi
			bzero(&mRegInfos[REG2(opcode)], sizeof(RegisterInfo));

			sscanf(&inLine->info.code[2], "%08x",
				&mRegInfos[REG2(opcode)].intValue);
			mRegInfos[REG2(opcode)].intValue	=
				OSSwapInt32(mRegInfos[REG2(opcode)].intValue);
			mRegInfos[REG2(opcode)].isValid	= true;

			break;

		default:
			break;
	}	// switch (opcode)
}

//	lineIsFunction:
// ————————————————————————————————————————————————————————————————————————————

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

	// Check for saved thunks.
	if (mThunks)
	{
		UInt32	i;

		for (i = 0; i < mNumThunks; i++)
		{
			if (mThunks[i].address == theAddy)
				return true;
		}
	}

	// Obvious avenues expended, brute force check now.
	BOOL	isFunction	= false;
	UInt8	opcode;

	sscanf(inLine->info.code, "%02hhx", &opcode);

	if (opcode == 0x55)	// pushl %ebp
		isFunction	= true;
	else
	{
		Line*	thePrevLine	= inLine->prev;

		while (thePrevLine)
		{
			if (thePrevLine->info.isCode)
				break;
			else
				thePrevLine	= thePrevLine->prev;
		}

		if (!thePrevLine)
			isFunction	= true;
	}

	return isFunction;
}

#pragma mark Deobfuscastion
//	verifyNops:
// ————————————————————————————————————————————————————————————————————————————

- (BOOL)verifyNops: (unsigned char***)outList
		  numFound: (UInt32*)outFound
{
	if (![self loadMachHeader])
	{
		printf("otx: failed to load mach header\n");
		return false;
	}

	[self loadLCommands];

	*outList	= [self searchForNopsIn: (unsigned char*)mTextSect.contents
		ofLength: mTextSect.size numFound: outFound];

	return *outFound != 0;
}

//	searchForNopsIn:OfLength:NumFound:OnlyByExistence:
// ————————————————————————————————————————————————————————————————————————————
//	Return value is a newly allocated list of addresses of 'outFound' length.
//	Caller owns the list.

- (unsigned char**)searchForNopsIn: (unsigned char*)inHaystack
				  ofLength: (UInt32)inHaystackLength
				  numFound: (UInt32*)outFound;
{
	unsigned char**	foundList			= nil;
	unsigned char	theSearchString[4]	= {0x00, 0x55, 0x89, 0xe5};
	unsigned char*	current;

	*outFound	= 0;

	// loop thru haystack
	for (current = inHaystack;
		 current <= inHaystack + inHaystackLength - 4;
		 current++)
	{
		if (memcmp(current, theSearchString, 4) != 0)
			continue;

		// Match for common benign occurences
		if (*(current - 4) == 0xe9	||	// jmpl
			*(current - 2) == 0xc2)		// ret
			continue;

		// Match for (not) common malignant occurences
		if (*(current - 7) != 0xe9	&&	// jmpl
			*(current - 5) != 0xe9	&&	// jmpl
			*(current - 4) != 0xeb	&&	// jmp
			*(current - 2) != 0xeb	&&	// jmp
			*(current - 5) != 0xc2	&&	// ret
			*(current - 5) != 0xca	&&	// ret
			*(current - 3) != 0xc2	&&	// ret
			*(current - 3) != 0xca	&&	// ret
			*(current - 3) != 0xc3	&&	// ret
			*(current - 3) != 0xcb	&&	// ret
			*(current - 1) != 0xc3	&&	// ret
			*(current - 1) != 0xcb)		// ret
			continue;

		(*outFound)++;

		if (foundList)
			foundList	= realloc(
				foundList, *outFound * sizeof(unsigned char*));
		else
			foundList	= malloc(sizeof(unsigned char*));

		foundList[*outFound - 1]	= current;
	}

	return foundList;
}

//	fixNops:
// ————————————————————————————————————————————————————————————————————————————

- (NSURL*)fixNops: (NopList*)inList
		   toPath: (NSString*)inOutputFilePath
{
	UInt32			i	= 0;
	unsigned char*	item;

	for (i = 0; i < inList->count; i++)
	{
		item	= inList->list[i];

		// For some unknown reason, the following direct memory accesses make
		// the app crash when running inside MallocDebug. Until the cause is
		// found, comment them out when looking for memory leaks.

		// This appears redundant, but to avoid false positives, we must
		// check jumps first(in decreasing size) and return statements last.
		if (*(item - 7) == 0xe9)		// e9xxxxxxxx0000005589e5
		{
			*(item)		= 0x90;
			*(item - 1)	= 0x90;
			*(item - 2)	= 0x90;
		}
		else if (*(item - 5) == 0xe9)	// e9xxxxxxxx005589e5
		{
			*(item)		= 0x90;
		}
		else if (*(item - 4) == 0xeb)	// ebxx0000005589e5
		{
			*(item)		= 0x90;
			*(item - 1)	= 0x90;
			*(item - 2)	= 0x90;
		}
		else if (*(item - 2) == 0xeb)	// ebxx005589e5
		{
			*(item)		= 0x90;
		}
		else if (*(item - 5) == 0xc2)	// c2xxxx0000005589e5
		{
			*(item)		= 0x90;
			*(item - 1)	= 0x90;
			*(item - 2)	= 0x90;
		}
		else if (*(item - 5) == 0xca)	// caxxxx0000005589e5
		{
			*(item)		= 0x90;
			*(item - 1)	= 0x90;
			*(item - 2)	= 0x90;
		}
		else if (*(item - 3) == 0xc2)	// c2xxxx005589e5
		{
			*(item)		= 0x90;
		}
		else if (*(item - 3) == 0xca)	// caxxxx005589e5
		{
			*(item)		= 0x90;
		}
		else if (*(item - 3) == 0xc3)	// c30000005589e5
		{
			*(item)		= 0x90;
			*(item - 1)	= 0x90;
			*(item - 2)	= 0x90;
		}
		else if (*(item - 3) == 0xcb)	// cb0000005589e5
		{
			*(item)		= 0x90;
			*(item - 1)	= 0x90;
			*(item - 2)	= 0x90;
		}
		else if (*(item - 1) == 0xc3)	// c3005589e5
		{
			*(item)		= 0x90;
		}
		else if (*(item - 1) == 0xcb)	// cb005589e5
		{
			*(item)		= 0x90;
		}
	}

	// Write data to a new file.
	NSData*		newFile	= [NSData dataWithBytesNoCopy: mRAMFile
		length: mRAMFileSize];

	if (!newFile)
	{
		printf("otx: -[X86Processor fixNops]: "
			"unable to create NSData for new file.\n");
		return nil;
	}

	NSError*	error	= nil;
	NSURL*		newURL	= [[NSURL alloc] initFileURLWithPath:
		[[[inOutputFilePath stringByDeletingLastPathComponent]
		stringByAppendingPathComponent: [[mOFile path] lastPathComponent]]
		stringByAppendingString: @"_fixed"]];

	[newURL autorelease];

	if (![newFile writeToURL: newURL options: NSAtomicWrite
		error: &error])
	{
		if (error)
			printf("otx: -[X86Processor fixNops]: "
				"unable to write to new file. %s\n",
				CSTRING([error localizedDescription]));
		else
			printf("otx: -[X86Processor fixNops]: "
				"unable to write to new file.\n");

		return nil;
	}

	// Copy original app's permissions to new file.
	NSFileManager*	fileMan		= [NSFileManager defaultManager];
	NSDictionary*	fileAttrs	= [fileMan fileAttributesAtPath:
		[mOFile path] traverseLink: false];

	if (!fileAttrs)
	{
		printf("otx: unable to read attributes from executable\n");
		return nil;
	}

	NSDictionary*	permsDict	= [NSDictionary dictionaryWithObjectsAndKeys:
		[NSNumber numberWithUnsignedInt: [fileAttrs filePosixPermissions]],
		NSFilePosixPermissions, nil];

	if (![fileMan changeFileAttributes: permsDict atPath: [newURL path]])
	{
		printf(
			"otx: unable to change file permissions for fixed executable\n");
	}

	// Return fixed file.
	return newURL;
}

@end
