/*
	ObjcAccessors.m

	What the filename says.

	This file is in the public domain.
*/

#import "ObjcAccessors.h"

@implementation ExeProcessor (ObjcAccessors)

//	getObjcClassPtr:fromMethod:
// ----------------------------------------------------------------------------
//	Given a method imp address, return the class to which it belongs. This func
//	is called each time a new function is detected. If that function is known
//	to be an Obj-C method, it's class is returned. Otherwise this returns nil.

- (BOOL)getObjcClassPtr: (objc_class**)outClass
			 fromMethod: (UInt32)inAddress;
{
	*outClass	= nil;

	MethodInfo*	theInfo	= nil;

	FindClassMethodByAddress(&theInfo, inAddress);

	if (theInfo)
		*outClass	= &theInfo->oc_class;

	return (*outClass != nil);
}

//	getObjcCatPtr:fromMethod:
// ----------------------------------------------------------------------------
//	Same as above, for categories.

- (BOOL)getObjcCatPtr: (objc_category**)outCat
		   fromMethod: (UInt32)inAddress;
{
	*outCat	= nil;

	MethodInfo*	theInfo	= nil;

	FindCatMethodByAddress(&theInfo, inAddress);

	if (theInfo)
		*outCat	= &theInfo->oc_cat;

	return (*outCat != nil);
}

//	getObjcMethod:fromAddress:
// ----------------------------------------------------------------------------
//	Given a method imp address, return the MethodInfo for it.

- (BOOL)getObjcMethod: (MethodInfo**)outMI
		  fromAddress: (UInt32)inAddress;
{
	*outMI	= nil;

	FindClassMethodByAddress(outMI, inAddress);

	if (*outMI)
		return true;

	FindCatMethodByAddress(outMI, inAddress);

	return (*outMI != nil);
}

//	getObjcMethodList:andMethods:fromAddress: (was get_method_list)
// ----------------------------------------------------------------------------
//	Removed the truncation flag. 'left' is no longer used by the caller.

- (BOOL)getObjcMethodList: (objc_method_list*)outList
			   andMethods: (objc_method**)outMethods
			  fromAddress: (UInt32)inAddress;
{
	UInt32	left, i;

	if (!outList)
		return false;

	*outList	= (objc_method_list){0};

	for (i = 0; i < mNumObjcSects; i++)
	{
		if (inAddress >= mObjcSects[i].s.addr &&
			inAddress < mObjcSects[i].s.addr + mObjcSects[i].s.size)
		{
			left = mObjcSects[i].s.size -
				(inAddress - mObjcSects[i].s.addr);

			if (left >= sizeof(objc_method_list) - sizeof(objc_method))
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

			return true;
		}
	}

	return false;
}

//	getObjcDescription:fromObject:type:
// ----------------------------------------------------------------------------
//	Given an Obj-C object, return it's description.

- (BOOL)getObjcDescription: (char**)outDescription
				fromObject: (const char*)inObject
					  type: (UInt8)inType
{
	*outDescription	= nil;

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
			return false;
			break;
	}

	if (mSwapped)
		theValue	= OSSwapInt32(theValue);

	*outDescription	= GetPointer(theValue, nil);

	return (*outDescription != nil);
}

//	getObjcSymtab:andDefs:fromModule: (was get_symtab)
// ----------------------------------------------------------------------------
//	Removed the truncation flag. 'left' is no longer used by the caller.

- (BOOL)getObjcSymtab: (objc_symtab*)outSymTab
			  andDefs: (void***)outDefs
		   fromModule: (objc_module*)inModule;
{
	if (!outSymTab)
		return false;

	unsigned long	addr	= (unsigned long)inModule->symtab;
	unsigned long	i, left;

	*outSymTab	= (objc_symtab){0};

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
			inDef < mObjcSects[i].s.addr + mObjcSects[i].s.size)
		{
			*outCat	= *(objc_category*)(mObjcSects[i].contents +
				(inDef - mObjcSects[i].s.addr));

			return true;
		}
	}

	return false;
}

//	getObjcClass:fromName:
// ----------------------------------------------------------------------------
//	Given a class name, return the class itself. This func is used to tie
//	categories to classes. We have 2 pointers to the same name, so pointer
//	equality is sufficient.

- (BOOL)getObjcClass: (objc_class*)outClass
			fromName: (const char*)inName;
{
	UInt32		i;

	for (i = 0; i < mNumClassMethodInfos; i++)
	{
		if (GetPointer(
			(UInt32)mClassMethodInfos[i].oc_class.name, nil) == inName)
		{
			*outClass	= mClassMethodInfos[i].oc_class;
			return true;
		}
	}

	*outClass	= (objc_class){0};

	return false;
}

//	getObjcMetaClass:fromClass:
// ----------------------------------------------------------------------------

- (BOOL)getObjcMetaClass: (objc_class*)outClass
			   fromClass: (objc_class*)inClass;
{
	if ((UInt32)inClass->isa >= mMetaClassSect.s.addr &&
		(UInt32)inClass->isa < mMetaClassSect.s.addr + mMetaClassSect.s.size)
	{
		*outClass	= *(objc_class*)(mMetaClassSect.contents +
			((UInt32)inClass->isa - mMetaClassSect.s.addr));

		return true;
	}

	return false;
}

@end
