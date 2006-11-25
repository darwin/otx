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
		fat_header*	fh	= (fat_header*)mRAMFile;
		fat_arch*	fa	= (fat_arch*)(fh + 1);

		// fat_header and fat_arch are always big-endian. Swap if we're
		// running on intel.
		if (OSHostByteOrder() == OSLittleEndian)
		{
			swap_fat_header(fh, OSLittleEndian);				// one header
			swap_fat_arch(fa, fh->nfat_arch, OSLittleEndian);	// multiple archs
		}

		UInt32	i;

		// Find the mach header we want.
		for (i = 0; i < fh->nfat_arch && !mMachHeader; i++)
		{
			if (fa->cputype == mArchSelector)
			{
				mMachHeader	= (mach_header*)(mRAMFile + fa->offset);
				mArchMagic	= *(UInt32*)mMachHeader;
				mSwapped	= mArchMagic == MH_CIGAM;
			}

			fa++;	// next arch
		}

		if (!mMachHeader)
			fprintf(stderr, "otx: architecture not found in unibin\n");
	}
	else	// not a unibin, so mach header = start of file.
	{
		switch (mArchMagic)
		{
			case MH_CIGAM:
				mSwapped = true;	// fall thru
			case MH_MAGIC:
				mMachHeader	=  (mach_header*)mRAMFile;
				break;

			default:
				fprintf(stderr, "otx: unknown magic value: 0x%x\n", mArchMagic);
				break;
		}
	}

	if (!mMachHeader)
	{
		fprintf(stderr, "otx: mach header not found\n");
		return false;
	}

	if (mSwapped)
		swap_mach_header(mMachHeader, OSHostByteOrder());

	return true;
}

//	loadLCommands
// ----------------------------------------------------------------------------
//	From the mach_header ptr, loop thru the load commands for each segment.

- (void)loadLCommands
{
	// We need byte pointers for pointer arithmetic. Set a pointer to the 1st
	// load command.
	char*	ptr	= (char*)(mMachHeader + 1);
	UInt16	i;

	// Loop thru load commands.
	for (i = 0; i < mMachHeader->ncmds; i++)
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
				segment_command*	segPtr	= (segment_command*)ptr;

				if (mSwapped)
					swap_segment_command(segPtr, OSHostByteOrder());

				// Load a segment we're interested in.
				if (!strcmp(segPtr->segname, SEG_TEXT))
				{
					mTextOffset	= segPtr->vmaddr - segPtr->fileoff;
					[self loadSegment: segPtr];
				}
				else if (!strcmp(segPtr->segname, SEG_DATA))
				{
					[self loadSegment: segPtr];
				}
				else if (!strcmp(segPtr->segname, SEG_OBJC))
					[self loadSegment: segPtr];
				else if (!strcmp(segPtr->segname, "__IMPORT"))
					[self loadSegment: segPtr];

				break;
			}

			case LC_SYMTAB:
			{
				// Re-cast the original ptr as a symtab_command.
				symtab_command*	symTab	= (symtab_command*)ptr;

				if (mSwapped)
					swap_symtab_command(symTab, OSHostByteOrder());

				[self loadSymbols: symTab];

				break;
			}

			default:
				break;
		}

		// Point to the next command.
		ptr	+= theCommandCopy.cmdsize;
	}	// for(i = 0; i < mMachHeader->ncmds; i++)

	// Now that we have all the objc sections, we can load the objc modules.
	[self loadObjcModules];
}

//	loadSegment:
// ----------------------------------------------------------------------------
//	Given a pointer to a segment, loop thru its sections and save whatever
//	we'll need later.

- (void)loadSegment: (segment_command*)inSegPtr
{
	// Set a pointer to the first section.
	char*	ptr	= (char*)inSegPtr + sizeof(segment_command);
	UInt16	i;

	// 'swap_section' acts more like 'swap_sections'. It is possible to
	// loop thru unreadable sections and swap them one at a time. Fuck it.
	if (mSwapped)
		swap_section((section*)ptr, inSegPtr->nsects, OSHostByteOrder());

	// Loop thru sections.
	section*	theSect	= nil;

	for (i = 0; i < inSegPtr->nsects; i++)
	{
		theSect	= (section*)ptr;

		if (!strcmp(theSect->segname, SEG_OBJC))
		{
			[self loadObjcSection: theSect];
		}
		else if (!strcmp(theSect->segname, SEG_TEXT))
		{
			if (!strcmp(theSect->sectname, SECT_TEXT))
				[self loadTextSection: theSect];
			else if (!strncmp(theSect->sectname, "__coalesced_text", 16))
				[self loadCoalTextSection: theSect];
			else if (!strcmp(theSect->sectname, "__textcoal_nt"))
				[self loadCoalTextNTSection: theSect];
			else if (!strcmp(theSect->sectname, "__const"))
				[self loadConstTextSection: theSect];
			else if (!strcmp(theSect->sectname, "__cstring"))
				[self loadCStringSection: theSect];
			else if (!strcmp(theSect->sectname, "__literal4"))
				[self loadLit4Section: theSect];
			else if (!strcmp(theSect->sectname, "__literal8"))
				[self loadLit8Section: theSect];
		}
		else if (!strcmp(theSect->segname, SEG_DATA))
		{
			if (!strcmp(theSect->sectname, SECT_DATA))
				[self loadDataSection: theSect];
			else if (!strncmp(theSect->sectname, "__coalesced_data", 16))
				[self loadCoalDataSection: theSect];
			else if (!strcmp(theSect->sectname, "__datacoal_nt"))
				[self loadCoalDataNTSection: theSect];
			else if (!strcmp(theSect->sectname, "__const"))
				[self loadConstDataSection: theSect];
			else if (!strcmp(theSect->sectname, "__dyld"))
				[self loadDyldDataSection: theSect];
			else if (!strcmp(theSect->sectname, "__cfstring"))
				[self loadCFStringSection: theSect];
			else if (!strcmp(theSect->sectname, "__nl_symbol_ptr"))
				[self loadNonLazySymbolSection: theSect];
		}
		else if (!strcmp(theSect->segname, "__IMPORT"))
		{
			if (!strcmp(theSect->sectname, "__pointers"))
				[self loadImpPtrSection: theSect];
		}

		ptr	+= sizeof(section);
	}
}

//	loadSymbols:
// ----------------------------------------------------------------------------
//	This refers to the symbol table located in the SEG_LINKEDIT segment.
//	See loadObjcSymTabFromModule for ObjC symbols.

- (void)loadSymbols: (symtab_command*)inSymPtr
{
//	nlist(3) doesn't quite cut it...

	nlist*	theSyms	= (nlist*)((char*)mMachHeader + inSymPtr->symoff);
	UInt32	i;

	if (mSwapped)
		swap_nlist(theSyms, inSymPtr->nsyms, OSHostByteOrder());

	// loop thru symbols
	for (i = 0; i < inSymPtr->nsyms; i++)
	{
		nlist	theSym	= theSyms[i];

		if (theSym.n_value == 0)
			continue;

		if ((theSym.n_type & N_STAB) == 0)	// not a STAB
		{
			if ((theSym.n_type & N_SECT) != N_SECT)
				continue;

			mNumFuncSyms++;

			if (mFuncSyms)
				mFuncSyms	= realloc(mFuncSyms,
					mNumFuncSyms * sizeof(nlist*));
			else
				mFuncSyms	= malloc(sizeof(nlist*));

			mFuncSyms[mNumFuncSyms - 1]	= &theSyms[i];

#if _OTX_DEBUG_SYMBOLS_
			[self printSymbol: theSym];
#endif
		}

	}	// for (i = 0; i < inSymPtr->nsyms; i++)

	// Sort the symbols so we can use binary searches later.
	qsort(mFuncSyms, mNumFuncSyms, sizeof(nlist*),
		(int (*)(const void*, const void*))Sym_Compare);
}

//	loadDySymbols:
// ----------------------------------------------------------------------------

- (void)loadDySymbols: (dysymtab_command*)inSymPtr
{
	nlist*	theSyms	= (nlist*)((char*)mMachHeader + inSymPtr->indirectsymoff);
	UInt32	i;

	if (mSwapped)
		swap_nlist(theSyms, inSymPtr->nindirectsyms, OSHostByteOrder());

	// loop thru symbols
	for (i = 0; i < inSymPtr->nindirectsyms; i++)
	{
#if _OTX_DEBUG_DYSYMBOLS_
		nlist	theSym		= theSyms[i];

		[self printSymbol: theSym];
#endif
	}
}

//	loadObjcSection:
// ----------------------------------------------------------------------------

- (void)loadObjcSection: (section*)inSect
{
	mNumObjcSects++;

	if (mObjcSects)
		mObjcSects	= realloc(mObjcSects,
			mNumObjcSects * sizeof(section_info));
	else
		mObjcSects	= malloc(sizeof(section_info));

	mObjcSects[mNumObjcSects - 1]	= (section_info)
		{*inSect, (char*)mMachHeader + inSect->offset, inSect->size};

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
	char*			theMachPtr	= (char*)mMachHeader;
	char*			theModPtr;
	section_info*	theSectInfo;
	objc_module		theModule;
	UInt32			theModSize;
	objc_symtab		theSymTab;
	objc_class		theClass;
	objc_category	theCat;
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
		while (theModPtr < theMachPtr + theSectInfo->s.offset + theSectInfo->s.size)
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

				// Save class's instance method info.
				objc_method_list	theMethodList;
				objc_method*		theMethods;
				objc_method			theMethod;

				if ([self getObjcMethodList: &theMethodList
					andMethods: &theMethods
					fromAddress: (UInt32)theClass.methodLists])
				{
					for (k = 0; k < theMethodList.method_count; k++)
					{
						theMethod	= theMethods[k];

						if (mSwapped)
							swap_objc_method(&theMethod);

						MethodInfo	theMethInfo	=
							{theMethod, theClass, {0}, true};

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
				objc_class	theMetaClass;

				if ([self getObjcMetaClass: &theMetaClass
					fromClass: &theClass])
				{
					if ([self getObjcMethodList: &theMethodList
						andMethods: &theMethods
						fromAddress: (UInt32)theMetaClass.methodLists])
					{
						for (k = 0; k < theMethodList.method_count; k++)
						{
							theMethod	= theMethods[k];

							if (mSwapped)
								swap_objc_method(&theMethod);

							MethodInfo	theMethInfo	=
								{theMethod, theClass, {0}, false};

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

					if (theMetaClass.ivars)
					{	// trigger this code and win a free beer.
						fprintf(stderr, "otx: found meta class ivars!\n");
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

				// Categories are linked to classes by name only. Try to 
				// find the class for this category. May be nil.
				GetObjcClassFromName(&theClass,
					GetPointer((UInt32)theCat.class_name, nil));

				// Save category instance method info.
				objc_method_list	theMethodList;
				objc_method*		theMethods;
				objc_method			theMethod;

				if ([self getObjcMethodList: &theMethodList
					andMethods: &theMethods
					fromAddress: (UInt32)theCat.instance_methods])
				{
					for (k = 0; k < theMethodList.method_count; k++)
					{
						theMethod	= theMethods[k];

						if (mSwapped)
							swap_objc_method(&theMethod);

						MethodInfo	theMethInfo	=
							{theMethod, theClass, theCat, true};

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
					fromAddress: (UInt32)theCat.class_methods])
				{
					for (k = 0; k < theMethodList.method_count; k++)
					{
						theMethod	= theMethods[k];

						if (mSwapped)
							swap_objc_method(&theMethod);

						MethodInfo	theMethInfo	=
							{theMethod, theClass, theCat, false};

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
		(int (*)(const void*, const void*))MethodInfo_Compare);
	qsort(mCatMethodInfos, mNumCatMethodInfos, sizeof(MethodInfo),
		(int (*)(const void*, const void*))MethodInfo_Compare);
}

//	loadCStringSection:
// ----------------------------------------------------------------------------

- (void)loadCStringSection: (section*)inSect
{
	mCStringSect.s			= *inSect;
	mCStringSect.contents	= (char*)mMachHeader + inSect->offset;
	mCStringSect.size		= inSect->size;
}

//	loadNSStringSection:
// ----------------------------------------------------------------------------

- (void)loadNSStringSection: (section*)inSect
{
	mNSStringSect.s			= *inSect;
	mNSStringSect.contents	= (char*)mMachHeader + inSect->offset;
	mNSStringSect.size		= inSect->size;
}

//	loadClassSection:
// ----------------------------------------------------------------------------

- (void)loadClassSection: (section*)inSect
{
	mClassSect.s		= *inSect;
	mClassSect.contents	= (char*)mMachHeader + inSect->offset;
	mClassSect.size		= inSect->size;
}

//	loadMetaClassSection:
// ----------------------------------------------------------------------------

- (void)loadMetaClassSection: (section*)inSect
{
	mMetaClassSect.s		= *inSect;
	mMetaClassSect.contents	= (char*)mMachHeader + inSect->offset;
	mMetaClassSect.size		= inSect->size;
}

//	loadIVarSection:
// ----------------------------------------------------------------------------

- (void)loadIVarSection: (section*)inSect
{
	mIVarSect.s			= *inSect;
	mIVarSect.contents	= (char*)mMachHeader + inSect->offset;
	mIVarSect.size		= inSect->size;
}

//	loadObjcModSection:
// ----------------------------------------------------------------------------

- (void)loadObjcModSection: (section*)inSect
{
	mObjcModSect.s			= *inSect;
	mObjcModSect.contents	= (char*)mMachHeader + inSect->offset;
	mObjcModSect.size		= inSect->size;
}

//	loadObjcSymSection:
// ----------------------------------------------------------------------------

- (void)loadObjcSymSection: (section*)inSect
{
	mObjcSymSect.s			= *inSect;
	mObjcSymSect.contents	= (char*)mMachHeader + inSect->offset;
	mObjcSymSect.size		= inSect->size;
}

//	loadLit4Section:
// ----------------------------------------------------------------------------

- (void)loadLit4Section: (section*)inSect
{
	mLit4Sect.s			= *inSect;
	mLit4Sect.contents	= (char*)mMachHeader + inSect->offset;
	mLit4Sect.size		= inSect->size;
}

//	loadLit8Section:
// ----------------------------------------------------------------------------

- (void)loadLit8Section: (section*)inSect
{
	mLit8Sect.s			= *inSect;
	mLit8Sect.contents	= (char*)mMachHeader + inSect->offset;
	mLit8Sect.size		= inSect->size;
}

//	loadTextSection:
// ----------------------------------------------------------------------------

- (void)loadTextSection: (section*)inSect
{
	mTextSect.s			= *inSect;
	mTextSect.contents	= (char*)mMachHeader + inSect->offset;
	mTextSect.size		= inSect->size;

	mEndOfText	= mTextSect.s.addr + mTextSect.s.size;
}

//	loadConstTextSection:
// ----------------------------------------------------------------------------

- (void)loadConstTextSection: (section*)inSect
{
	mConstTextSect.s		= *inSect;
	mConstTextSect.contents	= (char*)mMachHeader + inSect->offset;
	mConstTextSect.size		= inSect->size;
}

//	loadCoalTextSection:
// ----------------------------------------------------------------------------

- (void)loadCoalTextSection: (section*)inSect
{
	mCoalTextSect.s			= *inSect;
	mCoalTextSect.contents	= (char*)mMachHeader + inSect->offset;
	mCoalTextSect.size		= inSect->size;
}

//	loadCoalTextNTSection:
// ----------------------------------------------------------------------------

- (void)loadCoalTextNTSection: (section*)inSect
{
	mCoalTextNTSect.s			= *inSect;
	mCoalTextNTSect.contents	= (char*)mMachHeader + inSect->offset;
	mCoalTextNTSect.size		= inSect->size;
}

//	loadDataSection:
// ----------------------------------------------------------------------------

- (void)loadDataSection: (section*)inSect
{
	mDataSect.s			= *inSect;
	mDataSect.contents	= (char*)mMachHeader + inSect->offset;
	mDataSect.size		= inSect->size;
}

//	loadCoalDataSection:
// ----------------------------------------------------------------------------

- (void)loadCoalDataSection: (section*)inSect
{
	mCoalDataSect.s			= *inSect;
	mCoalDataSect.contents	= (char*)mMachHeader + inSect->offset;
	mCoalDataSect.size		= inSect->size;
}

//	loadCoalDataNTSection:
// ----------------------------------------------------------------------------

- (void)loadCoalDataNTSection: (section*)inSect
{
	mCoalDataNTSect.s			= *inSect;
	mCoalDataNTSect.contents	= (char*)mMachHeader + inSect->offset;
	mCoalDataNTSect.size		= inSect->size;
}

//	loadConstDataSection:
// ----------------------------------------------------------------------------

- (void)loadConstDataSection: (section*)inSect
{
	mConstDataSect.s		= *inSect;
	mConstDataSect.contents	= (char*)mMachHeader + inSect->offset;
	mConstDataSect.size		= inSect->size;
}

//	loadDyldDataSection:
// ----------------------------------------------------------------------------

- (void)loadDyldDataSection: (section*)inSect
{
	mDyldSect.s			= *inSect;
	mDyldSect.contents	= (char*)mMachHeader + inSect->offset;
	mDyldSect.size		= inSect->size;

	if (mDyldSect.size < sizeof(dyld_data_section))
		return;

	dyld_data_section*	data	= (dyld_data_section*)mDyldSect.contents;

	mAddrDyldStubBindingHelper	= (UInt32)(data->dyld_stub_binding_helper);

	if (mSwapped)
		mAddrDyldStubBindingHelper	=
			OSSwapInt32(mAddrDyldStubBindingHelper);
}

//	loadCFStringSection:
// ----------------------------------------------------------------------------

- (void)loadCFStringSection: (section*)inSect
{
	mCFStringSect.s			= *inSect;
	mCFStringSect.contents	= (char*)mMachHeader + inSect->offset;
	mCFStringSect.size		= inSect->size;
}

//	loadNonLazySymbolSection:
// ----------------------------------------------------------------------------

- (void)loadNonLazySymbolSection: (section*)inSect
{
	mNLSymSect.s		= *inSect;
	mNLSymSect.contents	= (char*)mMachHeader + inSect->offset;
	mNLSymSect.size		= inSect->size;
}

//	loadImpPtrSection:
// ----------------------------------------------------------------------------

- (void)loadImpPtrSection: (section*)inSect
{
	mImpPtrSect.s			= *inSect;
	mImpPtrSect.contents	= (char*)mMachHeader + inSect->offset;
	mImpPtrSect.size		= inSect->size;
}

@end
