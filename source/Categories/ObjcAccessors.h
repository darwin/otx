/*
    ObjcAccessors.h

    What the filename says.

    This file is in the public domain.
*/

#import <Cocoa/Cocoa.h>

#import "Exe32Processor.h"

@interface Exe32Processor(ObjcAccessors)

- (BOOL)getObjcClassPtr: (objc1_32_class**)outClass
             fromMethod: (uint32_t)inAddress;
- (BOOL)getObjcCatPtr: (objc1_32_category**)outCat
           fromMethod: (uint32_t)inAddress;
- (BOOL)getObjcMethod: (MethodInfo**)outMI
          fromAddress: (uint32_t)inAddress;
- (BOOL)getObjcMethodList: (objc1_32_method_list*)outList
                  methods: (objc1_32_method**)outMethods
              fromAddress: (uint32_t)inAddress;
- (BOOL)getObjcDescription: (char**)outDescription
                fromObject: (const char*)inObject
                      type: (UInt8)inType;
- (BOOL)getObjcSymtab: (objc1_32_symtab*)outSymTab
                 defs: (uint32_t **)outDefs
           fromModule: (objc1_32_module*)inModule;
- (BOOL)getObjcClass: (objc1_32_class*)outClass
             fromDef: (uint32_t)inDef;
- (BOOL)getObjcCategory: (objc1_32_category*)outCat
                fromDef: (uint32_t)inDef;
- (BOOL)getObjcClass: (objc1_32_class*)outClass
            fromName: (const char*)inName;
- (BOOL)getObjcClassPtr: (objc1_32_class**)outClassPtr
               fromName: (const char*)inName;
- (BOOL)getObjcMetaClass: (objc1_32_class*)outClass
               fromClass: (objc1_32_class*)inClass;

@end
