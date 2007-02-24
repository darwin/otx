/*
	SmarterPopen.m
 
	SmarterPopen handled NSTask
 
	This file is in the public domain.
 */

#import "SmarterPopen.h"
#import "SystemIncludes.h"
#import <sys/syscall.h>

#ifdef USESMARTERPOPEN

@implementation SmarterPopen

- (id)init
{
    self = [super init];
    if (self != nil)
    {
        m_StatusOk = 0;
        m_ReturnData = nil;
    }
    return self;
}

- (OSStatus)runTask: (NSString*)inCmd 
           withArgs: (NSArray*)theArgs
{
    
    NSTask *task;
    task = [[NSTask alloc] init];
    [task setLaunchPath: inCmd];
    
    // TODO: Check the last argument to make sure its nil
    [task setArguments: theArgs];
    
    NSPipe *pipe;
    NSPipe *epipe;
    pipe = [NSPipe pipe];
    epipe = [NSPipe pipe]; 
    
    [task setStandardOutput: pipe];
    [task setStandardError: epipe]; 
    
    NSFileHandle *file, *efile;
    file = [pipe fileHandleForReading];
    efile = [epipe fileHandleForReading];
    
    // try and launch the task
    @try
	{
        [task launch];
    }
    @catch  (NSException* e)
    {
        fprintf(stderr, "otx: -[SmarterPopen runTask]: "
                "Error with '%s' unable to launch task. %s\n",
                UTF8STRING(inCmd),
                UTF8STRING([e reason]));
        [task release];
        return -1;
    }
    
    // read to end stdout and stderr
    m_ReturnData = [file readDataToEndOfFile];
    
    // check status
    if ( [task terminationStatus] != m_StatusOk)
    { 
        m_ReturnData = [efile readDataToEndOfFile]; //replace bad data with stderr 
        fprintf(stderr, "otx: -[SmarterPopen runTask]: "
                "Error '@s' returned %d\n",
                inCmd,
                [task terminationStatus]);
        [task release];
        return -1;
    }
    
    [task release];
    return noErr;
}    
    
- (NSString *) getResultAsString
{
    NSString* string = [[NSString alloc] initWithData:m_ReturnData encoding: NSUTF8StringEncoding];
    return [string autorelease];
}


@end

#endif // USESMARTERPOPEN
