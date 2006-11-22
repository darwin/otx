/*
	main.m
*/

#import <AppKit/NSApplication.h>
#import <Cocoa/Cocoa.h>

//#ifdef _OTX_CLI_
#ifdef OTX_CLI
#import "CLIController.h"
#endif

// ============================================================================

int main(
	int		argc,
	char*	argv[])
{
	if (NSAppKitVersionNumber < floor(NSAppKitVersionNumber10_4))
	{
		printf("otx requires Mac OS X 10.4 or higher.\n");
		return -1;
	}


//#ifdef _OTX_CLI_
// much thanx to Slava Karpenko and MS for this
#ifdef OTX_CLI
//#if defined(OTX_CLI)

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
