/*
	Searchers.m

	A category on ExeProcessor that contains the various binary search
	methods.

	This file is in the public domain.
*/

#import "Searchers.h"

@implementation ExeProcessor(Searchers)

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
		(COMPARISON_FUNC_TYPE)Sym_Compare) != nil);

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

	UInt32	swappedAddress	= inAddress;

	if (mSwapped)
		swappedAddress	= OSSwapInt32(swappedAddress);

	MethodInfo	searchKey	= {{nil, nil, (IMP)swappedAddress}, {0}, {0}, false};

	*outMI	= bsearch(&searchKey,
		mClassMethodInfos, mNumClassMethodInfos, sizeof(MethodInfo),
			(COMPARISON_FUNC_TYPE)
			(mSwapped ? MethodInfo_Compare_Swapped : MethodInfo_Compare));

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

	UInt32	swappedAddress	= inAddress;

	if (mSwapped)
		swappedAddress	= OSSwapInt32(swappedAddress);

	MethodInfo	searchKey	= {{nil, nil, (IMP)swappedAddress}, {0}, {0}, false};

	*outMI	= bsearch(&searchKey,
		mCatMethodInfos, mNumCatMethodInfos, sizeof(MethodInfo),
			(COMPARISON_FUNC_TYPE)
			(mSwapped ? MethodInfo_Compare_Swapped : MethodInfo_Compare));

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
	objc_class*			theClassPtr		= inClass;
	objc_class			theSwappedClass	= *theClassPtr;
	objc_class			theDummyClass	= {0};
	char*				theSuperName	= nil;
	objc_ivar_list*		theIvars;

	while (theClassPtr)
	{
//		if (mSwapped)
//			swap_objc_class(&theSwappedClass);

		theIvars	= (objc_ivar_list*)GetPointer(
			(UInt32)theSwappedClass.ivars, nil);

		if (!theIvars)
		{	// Try again with the superclass.
			theSuperName	= GetPointer(
				(UInt32)theClassPtr->super_class, nil);

			if (!theSuperName)
				break;

			if (!GetObjcClassFromName(&theDummyClass, theSuperName))
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

		if (!GetObjcClassFromName(&theDummyClass, theSuperName))
			break;

		theClassPtr	= &theDummyClass;
	}

	return false;
}

@end
