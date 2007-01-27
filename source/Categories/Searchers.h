/*
	Searchers.h

	A category on ExeProcessor that contains the various binary search
	methods.

	This file is in the public domain.
*/

#import "ExeProcessor.h"

@interface	ExeProcessor(Searchers)

- (BOOL)findSymbolByAddress: (UInt32)inAddress;
- (BOOL)findClassMethod: (MethodInfo**)outMI
			  byAddress: (UInt32)inAddress;
- (BOOL)findCatMethod: (MethodInfo**)outMI
			byAddress: (UInt32)inAddress;
- (BOOL)findIvar: (objc_ivar*)outIvar
		 inClass: (objc_class*)inClass
	  withOffset: (UInt32)inOffset;

@end
