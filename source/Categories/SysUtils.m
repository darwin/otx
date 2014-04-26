/*
    SysUtils.m

    This file is in the public domain.
*/

#import <Cocoa/Cocoa.h>
#import <Foundation/NSCharacterSet.h>

#import "SystemIncludes.h"  // for UTF8STRING()
#import "SysUtils.h"

@implementation NSObject(SysUtils)

//  checkOtool:
// ----------------------------------------------------------------------------

- (BOOL)checkOtool: (NSString*)filePath
{
    NSString* otoolPath = [self pathForTool: @"otool"];
    NSTask* otoolTask = [[[NSTask alloc] init] autorelease];
    NSPipe* silence = [NSPipe pipe];

    [otoolTask setLaunchPath: otoolPath];
    [otoolTask setStandardInput: [NSPipe pipe]];
    [otoolTask setStandardOutput: silence];
    [otoolTask setStandardError: silence];
    [otoolTask launch];
    [otoolTask waitUntilExit];

    return ([otoolTask terminationStatus] == 1);
}

//  pathForTool:
// ----------------------------------------------------------------------------

- (NSString*)pathForTool: (NSString*)toolName
{
    NSString* relToolBase = [NSString pathWithComponents:
        [NSArray arrayWithObjects: @"/", @"usr", @"bin", nil]];
    NSString* relToolPath = [relToolBase stringByAppendingPathComponent: toolName];
    NSString* xcrunToolPath = [relToolBase stringByAppendingPathComponent: @"xcrun"];
    NSTask* xcrunTask = [[[NSTask alloc] init] autorelease];
    NSPipe* xcrunPipe = [NSPipe pipe];
    NSArray* args = [NSArray arrayWithObjects: @"--find", toolName, nil];

    [xcrunTask setLaunchPath: xcrunToolPath];
    [xcrunTask setArguments: args];
    [xcrunTask setStandardInput: [NSPipe pipe]];
    [xcrunTask setStandardOutput: xcrunPipe];
    [xcrunTask launch];
    [xcrunTask waitUntilExit];

    int xcrunStatus = [xcrunTask terminationStatus];

    if (xcrunStatus == -1)
        return relToolPath;

    NSData* xcrunData = [[xcrunPipe fileHandleForReading] availableData];
    NSString* absToolPath = [[[NSString alloc] initWithBytes: [xcrunData bytes]
                                                      length: [xcrunData length]
                                                    encoding: NSUTF8StringEncoding] autorelease];

    return [absToolPath stringByTrimmingCharactersInSet:
        [NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

@end
