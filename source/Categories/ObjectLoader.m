/*
	ObjectLoader.m

	A category on ExeProcessor that contains all the loadXXX methods.
*/

#import "ObjectLoader.h"
#import "ObjcAccessors.h"

@implementation ExeProcessor (ObjectLoader)

//	loadMachHeader
// ----------------------------------------------------------------------------
//	Assuming mRAMFile points to RAM that contains the contents of the exe, we
//	can set our mach_header* to point to the appropriate mach header, whether
//	the exe is unibin or not.

- (BOOL)loadMachHeader
{
	// Convert possible unibin to a single arch.
	if (mArchMagic	== FAT_MAGIC ||
		mArchMagic	== FAT_CIGAM)
	{
		fat_header	fh		= *(fat_header*)mRAMFile;
		fat_arch*	faPtr	= (fat_arch*)((char*)mRAMFile + sizeof(fat_header));
		fat_arch	fa;

		// fat_header and fat_arch are always big-endian. Swap if we're
		// running on intel.
		if (OSHostByteOrder() == OSLittleEndian)
			swap_fat_header(&fh, OSLittleEndian);

		UInt32	i;

		// Find the mach header we want.
		for (i = 0; i < fh.nfat_arch && !mMachHeaderPtr; i++)
		{
			fa	= *faPtr;

			if (OSHostByteOrder() == OSLittleEndian)
				swap_fat_arch(&fa, 1, OSLittleEndian);

			if (fa.cputype == mArchSelector)
			{
				mMachHeaderPtr	= (mach_header*)(mRAMFile + fa.offset);
				mArchMagic		= *(UInt32*)mMachHeaderPtr;
				mSwapped		= mArchMagic == MH_CIGAM;
				break;
			}

			faPtr++;	// next arch
		}

		if (!mMachHeaderPtr)
			fprintf(stderr, "otx: architecture not found in unibin\n");
	}
	else	// not a unibin, so mach header = start of file.
	{
		switch (mArchMagic)
		{
			case MH_CIGAM:
				mSwapped = true;	// fall thru
			case MH_MAGIC:
				mMachHeaderPtr	=  (mach_header*)mRAMFile;
				break;

			default:
				fprintf(stderr, "otx: unknown magic value: 0x%x\n", mArchMagic);
				break;
		}
	}

	if (!mMachHeaderPtr)
	{
		fprintf(stderr, "otx: mach header not found\n");
		return false;
	}

	mMachHeader	= *mMachHeaderPtr;

	if (mSwapped)
		swap_mach_header(&mMachHeader, OSHostByteOrder());

	return true;
}

//	loadLCommands
// ----------------------------------------------------------------------------
//	From the mach_header ptr, loop thru the load commands for each segment.

- (void)loadLCommands
{
	// We need byte pointers for pointer arithmetic. Set a pointer to the 1st
	// load command.
	char*	ptr	= (char*)(mMachHeaderPtr + 1);
	UInt16	i;

	// Loop thru load commands.
	for (i = 0; i < mMachHeader.ncmds; i++)
	{
		// Copy the load_command so we can:
		// -Swap it if needed without double-swapping parts of segments
		//		and symtabs.
		// -Easily advance to next load_command at end of loop regardless
		//		of command type.
		load_command	theCommandCopy	= *(load_command*)ptr;

		if (mSwapped)
			swap_load_command(&theCommandCopy, OSHostByteOrder());

		switch (theCommandCopy.cmd)
		{
			case LC_SEGMENT:
			{
				// Re-cast the original ptr as a segment_command.
				segment_command	swappedSeg	= *(segment_command*)ptr;

				if (mSwapped)
					swap_segment_command(&swappedSeg, OSHostByteOrder());

				// Load a segment we're interested in.
				if (!strcmp(swappedSeg.segname, SEG_TEXT))
				{
					mTextOffset	= swappedSeg.vmaddr - swappedSeg.fileoff;
					[self loadSegment: (segment_command*)ptr];
				}
				else if (!strcmp(swappedSeg.segname, SEG_DATA))
					[self loadSegment: (segment_command*)ptr];
				else if (!strcmp(swappedSeg.segname, SEG_OBJC))
					[self loadSegment: (segment_command*)ptr];
				else if (!strcmp(swappedSeg.segname, "__IMPORT"))
					[self loadSegment: (segment_command*)ptr];

				break;
			}

			case LC_SYMTAB:
				// Re-cast the original ptr as a symtab_command.
				[self loadSymbols: (symtab_command*)ptr];

				break;

			case LC_DYSYMTAB:
				// Re-cast the original ptr as a dysymtab_command.
				[self loadDySymbols: (dysymtab_command*)ptr];

				break;

			default:
				break;
		}

		// Point to the next command.
		ptr	+= theCommandCopy.cmdsize;
	}	// for(i = 0; i < mMachHeaderPtr->ncmds; i++)

	// Now that we have all the objc sections, we can load the objc modules.
	[self loadObjcModules];
}

//	loadSegment:
// ----------------------------------------------------------------------------
//	Given a pointer to a segment, loop thru its sections and save whatever
//	we'll need later.

- (void)loadSegment: (segment_command*)inSegPtr
{
	segment_command	swappedSeg	= *inSegPtr;

	if (mSwapped)
		swap_segment_command(&swappedSeg, OSHostByteOrder());

	// Set a pointer to the first section.
	section*	sectionPtr	=
		(section*)((char*)inSegPtr + sizeof(segment_command));
	UInt16		i;

	// Loop thru sections.
	for (i = 0; i < swappedSeg.nsects; i++)
	{
		if (!strcmp(sectionPtr->segname, SEG_OBJC))
		{
			[self loadObjcSection: sectionPtr];
		}
		else if (!strcmp(sectionPtr->segname, SEG_TEXT))
		{
			if (!strcmp(sectionPtr->sectname, SECT_TEXT))
				[self loadTextSection: sectionPtr];
			else if (!strncmp(sectionPtr->sectname, "__coalesced_text", 16))
				[self loadCoalTextSection: sectionPtr];
			else if (!strcmp(sectionPtr->sectname, "__textcoal_nt"))
				[self loadCoalTextNTSection: sectionPtr];
			else if (!strcmp(sectionPtr->sectname, "__const"))
				[self loadConstTextSection: sectionPtr];
			else if (!strcmp(sectionPtr->sectname, "__cstring"))
				[self loadCStringSection: sectionPtr];
			else if (!strcmp(sectionPtr->sectname, "__literal4"))
				[self loadLit4Section: sectionPtr];
			else if (!strcmp(sectionPtr->sectname, "__literal8"))
				[self loadLit8Section: sectionPtr];
		}
		else if (!strcmp(sectionPtr->segname, SEG_DATA))
		{
			if (!strcmp(sectionPtr->sectname, SECT_DATA))
				[self loadDataSection: sectionPtr];
			else if (!strncmp(sectionPtr->sectname, "__coalesced_data", 16))
				[self loadCoalDataSection: sectionPtr];
			else if (!strcmp(sectionPtr->sectname, "__datacoal_nt"))
				[self loadCoalDataNTSection: sectionPtr];
			else if (!strcmp(sectionPtr->sectname, "__const"))
				[self loadConstDataSection: sectionPtr];
			else if (!strcmp(sectionPtr->sectname, "__dyld"))
				[self loadDyldDataSection: sectionPtr];
			else if (!strcmp(sectionPtr->sectname, "__cfstring"))
				[self loadCFStringSection: sectionPtr];
			else if (!strcmp(sectionPtr->sectname, "__nl_symbol_ptr"))
				[self loadNonLazySymbolSection: sectionPtr];
		}
		else if (!strcmp(sectionPtr->segname, "__IMPORT"))
		{
			if (!strcmp(sectionPtr->sectname, "__pointers"))
				[self loadImpPtrSection: sectionPtr];
		}

		sectionPtr++;
	}
}

//	loadSymbols:
// ----------------------------------------------------------------------------
//	This refers to the symbol table located in the SEG_LINKEDIT segment.
//	See loadObjcSymTabFromModule for ObjC symbols.

- (void)loadSymbols: (symtab_command*)inSymPtr
{
//	nlist(3) doesn't quite cut it...

	symtab_command	swappedSymTab	= *inSymPtr;

	if (mSwapped)
		swap_symtab_command(&swappedSymTab, OSHostByteOrder());

	nlist*	theSymPtr	= (nlist*)((char*)mMachHeaderPtr + swappedSymTab.symoff);
	nlist	theSym		= {0};
	UInt32	i;

	// loop thru symbols
	for (i = 0; i < swappedSymTab.nsyms; i++)
	{
		theSym	= theSymPtr[i];

		if (mSwapped)
			swap_nlist(&theSym, 1, OSHostByteOrder());

		if (theSym.n_value == 0)
			continue;

		if ((theSym.n_type & N_STAB) == 0)	// not a STAB
		{
			if ((theSym.n_type & N_SECT) != N_SECT)
				continue;

			mNumFuncSyms++;

			if (mFuncSyms)
				mFuncSyms	= realloc(mFuncSyms,
					mNumFuncSyms * sizeof(nlist));
			else
				mFuncSyms	= malloc(sizeof(nlist));

			mFuncSyms[mNumFuncSyms - 1]	= theSym;

#ifdef OTX_DEBUG
#if _OTX_DEBUG_SYMBOLS_
			[self printSymbol: theSym];
#endif
#endif
		}
	}	// for (i = 0; i < swappedSymTab.nsyms; i++)

	// Sort the symbols so we can use binary searches later.
	qsort(mFuncSyms, mNumFuncSyms, sizeof(nlist),
		(COMPARISON_FUNC_TYPE)Sym_Compare);
}

//	loadDySymbols:
// ----------------------------------------------------------------------------

- (void)loadDySymbols: (dysymtab_command*)inSymPtr
{
/*

	nlist	newList[1000];

#undef nlist

	nlist(CSTRING([mOFile path]), newList);

#define nlist				struct nlist

	UInt32	bs	= 0;

	while (newList[bs].n_un.n_name)
	{
		if (newList[bs].n_value)
		{
			[self printSymbol: newList[bs]];
		}

		bs++;
	}

	fprintf(stderr, "finished printing all syms\n");

*/
	dysymtab_command	swappedSymTab	= *inSymPtr;

	if (mSwapped)
		swap_dysymtab_command(&swappedSymTab, OSHostByteOrder());

	nlist*	theSymPtr	= (nlist*)
//		((char*)mMachHeaderPtr + swappedSymTab.indirectsymoff);
		((char*)mMachHeaderPtr + swappedSymTab.extrefsymoff);
	nlist	theSym		= {0};
	UInt32	i;

	// loop thru symbols
//	for (i = 0; i < swappedSymTab.nindirectsyms; i++)
	for (i = 0; i < swappedSymTab.nextrefsyms; i++)
	{
		theSym	= theSymPtr[i];

		if (mSwapped)
			swap_nlist(&theSym, 1, OSHostByteOrder());

		if (theSym.n_value == 0)
			continue;

		if ((theSym.n_type & N_STAB) == 0)	// not a STAB
		{
			mNumDySyms++;

			if (mDySyms)
				mDySyms	= realloc(mDySyms,
					mNumDySyms * sizeof(nlist));
			else
				mDySyms	= malloc(sizeof(nlist));

			mDySyms[mNumDySyms - 1]	= theSym;

#ifdef OTX_DEBUG
#if _OTX_DEBUG_DYSYMBOLS_
			[self printSymbol: theSym];
#endif
#endif
		}
	}	// for (i = 0; i < swappedSymTab.nextrefsyms; i++)

	// Sort the symbols so we can use binary searches later.
	qsort(mDySyms, mNumDySyms, sizeof(nlist),
		(COMPARISON_FUNC_TYPE)Sym_Compare);
}

//	loadObjcSection:
// ----------------------------------------------------------------------------

- (void)loadObjcSection: (section*)inSect
{
	section	swappedSect	= *inSect;

	if (mSwapped)
		swap_section(&swappedSect, 1, OSHostByteOrder());

	mNumObjcSects++;

	if (mObjcSects)
		mObjcSects	= realloc(mObjcSects,
			mNumObjcSects * sizeof(section_info));
	else
		mObjcSects	= malloc(sizeof(section_info));

	mObjcSects[mNumObjcSects - 1]	= (section_info)
		{swappedSect, (char*)mMachHeaderPtr + swappedSect.offset,
		swappedSect.size};

	if (!strncmp(inSect->sectname, "__cstring_object", 16))
		[self loadNSStringSection: inSect];
	else if (!strcmp(inSect->sectname, "__class"))
		[self loadClassSection: inSect];
	else if (!strcmp(inSect->sectname, "__meta_class"))
		[self loadMetaClassSection: inSect];
	else if (!strcmp(inSect->sectname, "__instance_vars"))
		[self loadIVarSection: inSect];
	else if (!strcmp(inSect->sectname, "__module_info"))
		[self loadObjcModSection: inSect];
	else if (!strcmp(inSect->sectname, "__symbols"))
		[self loadObjcSymSection: inSect];
}

//	loadObjcModules
// ----------------------------------------------------------------------------

- (void)loadObjcModules
{
	char*			theMachPtr	= (char*)mMachHeaderPtr;
	char*			theModPtr;
	section_info*	theSectInfo;
	objc_module		theModule;
	UInt32			theModSize;
	objc_symtab		theSymTab;
	objc_class		theClass, theSwappedClass, theMetaClass;
	objc_category	theCat, theSwappedCat;
	void**			theDefs;
	UInt32			theOffset;
	UInt32			i, j, k;

	// Loop thru objc sections.
	for (i = 0; i < mNumObjcSects; i++)
	{
		theSectInfo	= &mObjcSects[i];

		// Bail if not a module section.
		if (strcmp(theSectInfo->s.sectname, SECT_OBJC_MODULES))
			continue;

		theOffset	= theSectInfo->s.addr - theSectInfo->s.offset;
		theModPtr	= theMachPtr + theSectInfo->s.addr - theOffset;
		theModule	= *(objc_module*)theModPtr;

		if (mSwapped)
			swap_objc_module(&theModule);

		theModSize	= theModule.size;

		// Loop thru modules.
		while (theModPtr <
			theMachPtr + theSectInfo->s.offset + theSectInfo->s.size)
		{
			// Try to locate the objc_symtab for this module.
			if (![self getObjcSymtab: &theSymTab andDefs: &theDefs
				fromModule: &theModule] || !theDefs)
			{
				// point to next module
				theModPtr	+= theModSize;
				theModule	= *(objc_module*)theModPtr;

				if (mSwapped)
					swap_objc_module(&theModule);

				theModSize	= theModule.size;

				continue;
			}

			if (mSwapped)
				swap_objc_symtab(&theSymTab);

// In the objc_symtab struct defined in <objc/objc-runtime.h>, the format of
// the void* array 'defs' is 'cls_def_cnt' class pointers followed by
// 'cat_def_cnt' category pointers.
			UInt32	theDef;

			// Loop thru class definitions in the objc_symtab.
			for (j = 0; j < theSymTab.cls_def_cnt; j++)
			{
				// Try to locate the objc_class for this def.
				UInt32	theDef	= (UInt32)theDefs[j];

				if (mSwapped)
					theDef	= OSSwapInt32(theDef);

				if (![self getObjcClass: &theClass fromDef: theDef])
					continue;

				theSwappedClass	= theClass;

				if (mSwapped)
					swap_objc_class(&theSwappedClass);

				// Save class's instance method info.
				objc_method_list	theMethodList;
				objc_method*		theMethods;
				objc_method			theMethod;

				if ([self getObjcMethodList: &theMethodList
					andMethods: &theMethods
					fromAddress: (UInt32)theSwappedClass.methodLists])
				{
					if (mSwapped)
						swap_objc_method_list(&theMethodList);

					for (k = 0; k < theMethodList.method_count; k++)
					{
						theMethod	= theMethods[k];

						if (mSwapped)
							swap_objc_method(&theMethod);

						MethodInfo	theMethInfo	=
							{theMethod, theSwappedClass, {0}, true};

						mNumClassMethodInfos++;

						if (mClassMethodInfos)
							mClassMethodInfos	= realloc(mClassMethodInfos,
								mNumClassMethodInfos * sizeof(MethodInfo));
						else
							mClassMethodInfos	= malloc(sizeof(MethodInfo));

						mClassMethodInfos[mNumClassMethodInfos - 1]	= theMethInfo;
					}
				}

				// Save class's class method info.
				if ([self getObjcMetaClass: &theMetaClass
					fromClass: &theSwappedClass])
				{
					if (mSwapped)
						swap_objc_class(&theMetaClass);

					if ([self getObjcMethodList: &theMethodList
						andMethods: &theMethods
						fromAddress: (UInt32)theMetaClass.methodLists])
					{
						if (mSwapped)
							swap_objc_method_list(&theMethodList);

						for (k = 0; k < theMethodList.method_count; k++)
						{
							theMethod	= theMethods[k];

							if (mSwapped)
								swap_objc_method(&theMethod);

							MethodInfo	theMethInfo	=
								{theMethod, theSwappedClass, {0}, false};

							mNumClassMethodInfos++;

							if (mClassMethodInfos)
								mClassMethodInfos	= realloc(
									mClassMethodInfos, mNumClassMethodInfos *
									sizeof(MethodInfo));
							else
								mClassMethodInfos	=
									malloc(sizeof(MethodInfo));

							mClassMethodInfos[mNumClassMethodInfos - 1]	=
								theMethInfo;
						}
					}
				}	// theMetaClass != nil
			}

			// Loop thru category definitions in the objc_symtab.
			for (; j < theSymTab.cat_def_cnt + theSymTab.cls_def_cnt; j++)
			{
				// Try to locate the objc_category for this def.
				theDef	= (UInt32)theDefs[j];

				if (mSwapped)
					theDef	= OSSwapInt32(theDef);

				if (![self getObjcCategory: &theCat fromDef: theDef])
					continue;

				theSwappedCat	= theCat;

				if (mSwapped)
					swap_objc_category(&theSwappedCat);

				// Categories are linked to classes by name only. Try to 
				// find the class for this category. May be nil.
				GetObjcClassFromName(&theClass,
					GetPointer((UInt32)theSwappedCat.class_name, nil));

				theSwappedClass	= theClass;

				if (mSwapped)
					swap_objc_class(&theSwappedClass);

				// Save category instance method info.
				objc_method_list	theMethodList;
				objc_method*		theMethods;
				objc_method			theMethod;

				if ([self getObjcMethodList: &theMethodList
					andMethods: &theMethods
					fromAddress: (UInt32)theSwappedCat.instance_methods])
				{
					if (mSwapped)
						swap_objc_method_list(&theMethodList);

					for (k = 0; k < theMethodList.method_count; k++)
					{
						theMethod	= theMethods[k];

						if (mSwapped)
							swap_objc_method(&theMethod);

						MethodInfo	theMethInfo	=
							{theMethod, theSwappedClass, theSwappedCat, true};

						mNumCatMethodInfos++;

						if (mCatMethodInfos)
							mCatMethodInfos	= realloc(mCatMethodInfos,
								mNumCatMethodInfos * sizeof(MethodInfo));
						else
							mCatMethodInfos	= malloc(sizeof(MethodInfo));

						mCatMethodInfos[mNumCatMethodInfos - 1]	= theMethInfo;
					}
				}

				// Save category class method info.
				if ([self getObjcMethodList: &theMethodList
					andMethods: &theMethods
					fromAddress: (UInt32)theSwappedCat.class_methods])
				{
					if (mSwapped)
						swap_objc_method_list(&theMethodList);

					for (k = 0; k < theMethodList.method_count; k++)
					{
						theMethod	= theMethods[k];

						if (mSwapped)
							swap_objc_method(&theMethod);

						MethodInfo	theMethInfo	=
							{theMethod, theSwappedClass, theSwappedCat, false};

						mNumCatMethodInfos++;

						if (mCatMethodInfos)
							mCatMethodInfos	=
							realloc(mCatMethodInfos,
								mNumCatMethodInfos * sizeof(MethodInfo));
						else
							mCatMethodInfos	= malloc(sizeof(MethodInfo));

						mCatMethodInfos[mNumCatMethodInfos - 1]	= theMethInfo;
					}
				}
			}	// for (; j < theSymTab.cat_def_cnt; j++)

			// point to next module
			theModPtr	+= theModSize;
			theModule	= *(objc_module*)theModPtr;

			if (mSwapped)
				swap_objc_module(&theModule);

			theModSize	= theModule.size;
		}	// while (theModPtr...)
	}	// for (i = 0; i < mNumObjcSects; i++)

	// Sort MethodInfos.
	qsort(mClassMethodInfos, mNumClassMethodInfos, sizeof(MethodInfo),
		(COMPARISON_FUNC_TYPE)MethodInfo_Compare);
	qsort(mCatMethodInfos, mNumCatMethodInfos, sizeof(MethodInfo),
		(COMPARISON_FUNC_TYPE)MethodInfo_Compare);
}

//	loadCStringSection:
// ----------------------------------------------------------------------------

- (void)loadCStringSection: (section*)inSect
{
	mCStringSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mCStringSect.s, 1, OSHostByteOrder());

	mCStringSect.contents	= (char*)mMachHeaderPtr + mCStringSect.s.offset;
	mCStringSect.size		= mCStringSect.s.size;
}

//	loadNSStringSection:
// ----------------------------------------------------------------------------

- (void)loadNSStringSection: (section*)inSect
{
	mNSStringSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mNSStringSect.s, 1, OSHostByteOrder());

	mNSStringSect.contents	= (char*)mMachHeaderPtr + mNSStringSect.s.offset;
	mNSStringSect.size		= mNSStringSect.s.size;
}

//	loadClassSection:
// ----------------------------------------------------------------------------

- (void)loadClassSection: (section*)inSect
{
	mClassSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mClassSect.s, 1, OSHostByteOrder());

	mClassSect.contents	= (char*)mMachHeaderPtr + mClassSect.s.offset;
	mClassSect.size		= mClassSect.s.size;
}

//	loadMetaClassSection:
// ----------------------------------------------------------------------------

- (void)loadMetaClassSection: (section*)inSect
{
	mMetaClassSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mMetaClassSect.s, 1, OSHostByteOrder());

	mMetaClassSect.contents	= (char*)mMachHeaderPtr + mMetaClassSect.s.offset;
	mMetaClassSect.size		= mMetaClassSect.s.size;
}

//	loadIVarSection:
// ----------------------------------------------------------------------------

- (void)loadIVarSection: (section*)inSect
{
	mIVarSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mIVarSect.s, 1, OSHostByteOrder());

	mIVarSect.contents	= (char*)mMachHeaderPtr + mIVarSect.s.offset;
	mIVarSect.size		= mIVarSect.s.size;
}

//	loadObjcModSection:
// ----------------------------------------------------------------------------

- (void)loadObjcModSection: (section*)inSect
{
	mObjcModSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mObjcModSect.s, 1, OSHostByteOrder());

	mObjcModSect.contents	= (char*)mMachHeaderPtr + mObjcModSect.s.offset;
	mObjcModSect.size		= mObjcModSect.s.size;
}

//	loadObjcSymSection:
// ----------------------------------------------------------------------------

- (void)loadObjcSymSection: (section*)inSect
{
	mObjcSymSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mObjcSymSect.s, 1, OSHostByteOrder());

	mObjcSymSect.contents	= (char*)mMachHeaderPtr + mObjcSymSect.s.offset;
	mObjcSymSect.size		= mObjcSymSect.s.size;
}

//	loadLit4Section:
// ----------------------------------------------------------------------------

- (void)loadLit4Section: (section*)inSect
{
	mLit4Sect.s	= *inSect;

	if (mSwapped)
		swap_section(&mLit4Sect.s, 1, OSHostByteOrder());

	mLit4Sect.contents	= (char*)mMachHeaderPtr + mLit4Sect.s.offset;
	mLit4Sect.size		= mLit4Sect.s.size;
}

//	loadLit8Section:
// ----------------------------------------------------------------------------

- (void)loadLit8Section: (section*)inSect
{
	mLit8Sect.s	= *inSect;

	if (mSwapped)
		swap_section(&mLit8Sect.s, 1, OSHostByteOrder());

	mLit8Sect.contents	= (char*)mMachHeaderPtr + mLit8Sect.s.offset;
	mLit8Sect.size		= mLit8Sect.s.size;
}

//	loadTextSection:
// ----------------------------------------------------------------------------

- (void)loadTextSection: (section*)inSect
{
	mTextSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mTextSect.s, 1, OSHostByteOrder());

	mTextSect.contents	= (char*)mMachHeaderPtr + mTextSect.s.offset;
	mTextSect.size		= mTextSect.s.size;

	mEndOfText	= mTextSect.s.addr + mTextSect.s.size;
}

//	loadConstTextSection:
// ----------------------------------------------------------------------------

- (void)loadConstTextSection: (section*)inSect
{
	mConstTextSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mConstTextSect.s, 1, OSHostByteOrder());

	mConstTextSect.contents	= (char*)mMachHeaderPtr + mConstTextSect.s.offset;
	mConstTextSect.size		= mConstTextSect.s.size;
}

//	loadCoalTextSection:
// ----------------------------------------------------------------------------

- (void)loadCoalTextSection: (section*)inSect
{
	mCoalTextSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mCoalTextSect.s, 1, OSHostByteOrder());

	mCoalTextSect.contents	= (char*)mMachHeaderPtr + mCoalTextSect.s.offset;
	mCoalTextSect.size		= mCoalTextSect.s.size;
}

//	loadCoalTextNTSection:
// ----------------------------------------------------------------------------

- (void)loadCoalTextNTSection: (section*)inSect
{
	mCoalTextNTSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mCoalTextNTSect.s, 1, OSHostByteOrder());

	mCoalTextNTSect.contents	= (char*)mMachHeaderPtr + mCoalTextNTSect.s.offset;
	mCoalTextNTSect.size		= mCoalTextNTSect.s.size;
}

//	loadDataSection:
// ----------------------------------------------------------------------------

- (void)loadDataSection: (section*)inSect
{
	mDataSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mDataSect.s, 1, OSHostByteOrder());

	mDataSect.contents	= (char*)mMachHeaderPtr + mDataSect.s.offset;
	mDataSect.size		= mDataSect.s.size;
}

//	loadCoalDataSection:
// ----------------------------------------------------------------------------

- (void)loadCoalDataSection: (section*)inSect
{
	mCoalDataSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mCoalDataSect.s, 1, OSHostByteOrder());

	mCoalDataSect.contents	= (char*)mMachHeaderPtr + mCoalDataSect.s.offset;
	mCoalDataSect.size		= mCoalDataSect.s.size;
}

//	loadCoalDataNTSection:
// ----------------------------------------------------------------------------

- (void)loadCoalDataNTSection: (section*)inSect
{
	mCoalDataNTSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mCoalDataNTSect.s, 1, OSHostByteOrder());

	mCoalDataNTSect.contents	= (char*)mMachHeaderPtr + mCoalDataNTSect.s.offset;
	mCoalDataNTSect.size		= mCoalDataNTSect.s.size;
}

//	loadConstDataSection:
// ----------------------------------------------------------------------------

- (void)loadConstDataSection: (section*)inSect
{
	mConstDataSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mConstDataSect.s, 1, OSHostByteOrder());

	mConstDataSect.contents	= (char*)mMachHeaderPtr + mConstDataSect.s.offset;
	mConstDataSect.size		= mConstDataSect.s.size;
}

//	loadDyldDataSection:
// ----------------------------------------------------------------------------

- (void)loadDyldDataSection: (section*)inSect
{
	mDyldSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mDyldSect.s, 1, OSHostByteOrder());

	mDyldSect.contents	= (char*)mMachHeaderPtr + mDyldSect.s.offset;
	mDyldSect.size		= mDyldSect.s.size;

	if (mDyldSect.size < sizeof(dyld_data_section))
		return;

	dyld_data_section*	data	= (dyld_data_section*)mDyldSect.contents;

	mAddrDyldStubBindingHelper	= (UInt32)(data->dyld_stub_binding_helper);

	if (mSwapped)
		mAddrDyldStubBindingHelper	= OSSwapInt32(mAddrDyldStubBindingHelper);
}

//	loadCFStringSection:
// ----------------------------------------------------------------------------

- (void)loadCFStringSection: (section*)inSect
{
	mCFStringSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mCFStringSect.s, 1, OSHostByteOrder());

	mCFStringSect.contents	= (char*)mMachHeaderPtr + mCFStringSect.s.offset;
	mCFStringSect.size		= mCFStringSect.s.size;
}

//	loadNonLazySymbolSection:
// ----------------------------------------------------------------------------

- (void)loadNonLazySymbolSection: (section*)inSect
{
	mNLSymSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mNLSymSect.s, 1, OSHostByteOrder());

	mNLSymSect.contents	= (char*)mMachHeaderPtr + mNLSymSect.s.offset;
	mNLSymSect.size		= mNLSymSect.s.size;
}

//	loadImpPtrSection:
// ----------------------------------------------------------------------------

- (void)loadImpPtrSection: (section*)inSect
{
	mImpPtrSect.s	= *inSect;

	if (mSwapped)
		swap_section(&mImpPtrSect.s, 1, OSHostByteOrder());

	mImpPtrSect.contents	= (char*)mMachHeaderPtr + mImpPtrSect.s.offset;
	mImpPtrSect.size		= mImpPtrSect.s.size;
}

@end
