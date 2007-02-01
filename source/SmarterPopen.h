/*
	SmarterPopen.h
 
	SmarterPopen ObjC bridge to popen()
 
	This file is in the public domain.
 */

#import <Cocoa/Cocoa.h>
#ifdef USESMARTERPOPEN

@interface SmarterPopen : NSObject {

}

- (BOOL)openPipe: (NSString*)inCode;

@end

#endif // USESMARTERPOPEN