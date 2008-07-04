/*
    Searchers.h

    A category on Exe32Processor that contains the various binary search
    methods.

    This file is in the public domain.
*/

#import <Cocoa/Cocoa.h>

#import "Exe32Processor.h"

@interface Exe32Processor(Searchers)

- (BOOL)findSymbolByAddress: (UInt32)inAddress;
- (BOOL)findClassMethod: (MethodInfo**)outMI
              byAddress: (UInt32)inAddress;
- (BOOL)findCatMethod: (MethodInfo**)outMI
            byAddress: (UInt32)inAddress;
- (BOOL)findIvar: (objc_ivar*)outIvar
         inClass: (objc_class*)inClass
      withOffset: (UInt32)inOffset;

@end
