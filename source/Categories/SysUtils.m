/*
    SysUtils.m

    This file is in the public domain.
*/

#import <Cocoa/Cocoa.h>
#import <Foundation/NSCharacterSet.h>

#import "SystemIncludes.h"  // for UTF8STRING()
#import "SysUtils.h"

@implementation NSObject(SysUtils)

//  checkOtool:inputFile:
// ----------------------------------------------------------------------------

- (SInt32)checkOtool: (NSString*)filePath
{
    NSString*   otoolPath = [self pathForTool: @"otool"];
    NSString*   otoolString = [NSString stringWithFormat:
        @"%@ -h \"%@\" > /dev/null", otoolPath, filePath];

    return system(UTF8STRING(otoolString));
}

//  pathForTool:
// ----------------------------------------------------------------------------

- (NSString*)pathForTool: (NSString*)toolName
{
    NSString* relToolBase = [NSString pathWithComponents:
        [NSArray arrayWithObjects: @"/", @"usr", @"bin", nil]];
    NSString* relToolPath = [relToolBase stringByAppendingPathComponent: toolName];
    NSString* selectToolPath = [relToolBase stringByAppendingPathComponent: @"xcode-select"];
    NSTask* selectTask = [[[NSTask alloc] init] autorelease];
    NSPipe* selectPipe = [NSPipe pipe];
    NSArray* args = [NSArray arrayWithObject: @"--print-path"];

    [selectTask setLaunchPath: selectToolPath];
    [selectTask setArguments: args];
    [selectTask setStandardOutput: selectPipe];
    [selectTask launch];
    [selectTask waitUntilExit];

    int selectStatus = [selectTask terminationStatus];

    if (selectStatus == -1)
        return relToolPath;

    NSData* selectData = [[selectPipe fileHandleForReading] availableData];
    NSString* absToolPath = [[[NSString alloc] initWithBytes: [selectData bytes]
                                                      length: [selectData length]
                                                    encoding: NSUTF8StringEncoding] autorelease];

    return [[absToolPath stringByTrimmingCharactersInSet:
        [NSCharacterSet whitespaceAndNewlineCharacterSet]]
        stringByAppendingPathComponent: relToolPath];
}

@end
