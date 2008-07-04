/*
    SysUtils.h

    This file is in the public domain.
*/

#import <Cocoa/Cocoa.h>

@interface NSObject(SysUtils)

- (SInt32)checkOtool: (NSString*)filePath;
- (NSString*)pathForTool: (NSString*)toolName;

@end