/*
	SmarterPopen.h
 
	SmarterPopen ObjC bridge to popen()
 
	This file is in the public domain.
 */

#import <Cocoa/Cocoa.h>
#ifdef USESMARTERPOPEN

@interface SmarterPopen : NSObject 
{
    int  m_StatusOk;
    NSData * m_ReturnData;
}

- (OSStatus)runTask: (NSString*) inCmd withArgs:(NSArray*) theArgs;
- (NSString *) getResultAsString;

@end

#endif // USESMARTERPOPEN