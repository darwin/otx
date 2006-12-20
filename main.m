/*
	main.m

	This file is in the public domain.
*/

#import <AppKit/NSApplication.h>

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
		fprintf(stderr, "otx requires Mac OS X 10.4 or higher.\n");
		return -1;
	}

// OTX_CLI is defined in the CLI target settings. Much thanx to Slava Karpenko
// and Mike Solomon for telling me about the -D flag.
#ifdef OTX_CLI

	NSAutoreleasePool*	pool		= [[NSAutoreleasePool alloc] init];
	CLIController*		controller	=
		[[CLIController alloc] initWithArgs: argv count: argc];

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
