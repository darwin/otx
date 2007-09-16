/*
	ObjcAccessors.h

	What the filename says.

	This file is in the public domain.
*/

#import "ExeProcessor.h"

@interface ExeProcessor(ObjcAccessors)

- (BOOL)getObjcClassPtr: (objc_class**)outClass
			 fromMethod: (UInt32)inAddress;
- (BOOL)getObjcCatPtr: (objc_category**)outCat
		   fromMethod: (UInt32)inAddress;
- (BOOL)getObjcMethod: (MethodInfo**)outMI
		  fromAddress: (UInt32)inAddress;
- (BOOL)getObjcMethodList: (objc_method_list*)outList
				  methods: (objc_method**)outMethods
			  fromAddress: (UInt32)inAddress;
- (BOOL)getObjcDescription: (char**)outDescription
				fromObject: (const char*)inObject
					  type: (UInt8)inType;
- (BOOL)getObjcSymtab: (objc_symtab*)outSymTab
				 defs: (void***)outDefs
		   fromModule: (objc_module*)inModule;
- (BOOL)getObjcClass: (objc_class*)outClass
			 fromDef: (UInt32)inDef;
- (BOOL)getObjcCategory: (objc_category*)outCat
				fromDef: (UInt32)inDef;
- (BOOL)getObjcClass: (objc_class*)outClass
			fromName: (const char*)inName;
- (BOOL)getObjcClassPtr: (objc_class**)outClassPtr
			   fromName: (const char*)inName;
- (BOOL)getObjcMetaClass: (objc_class*)outClass
			   fromClass: (objc_class*)inClass;

@end
