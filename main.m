/*
	main.m
*/

#import <AppKit/NSApplication.h>
#import <Cocoa/Cocoa.h>

#ifdef _OTX_CLI_
#import "CLIController.h"
#endif

// ============================================================================

int main(
	int		argc,
	char*	argv[])
{
	if (NSAppKitVersionNumber < floor(NSAppKitVersionNumber10_4))
		return noErr;

#ifdef _OTX_CLI_

	NSAutoreleasePool*	pool	= [[NSAutoreleasePool alloc] init];

	CLIController*	controller	= [[CLIController alloc] initWithArgs:
		argv count: argc];

	if (!controller)
		return -1;

	[controller processFile: nil];
	[controller release];
	[pool release];

	return noErr;

#else

	return NSApplicationMain(argc, (const char**)argv);

#endif
}
