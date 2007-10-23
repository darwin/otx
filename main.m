/*
	main.m

	This file is in the public domain.
*/

#ifdef OTX_CLI
	#import "CLIController.h"
#else
	#import <AppKit/NSApplication.h>
#endif

// ============================================================================

int main(
	int		argc,
	char*	argv[])
{
	if (OS_IS_PRE_TIGER)
	{
		fprintf(stderr, "otx requires Mac OS X 10.4 or higher.\n");
		return -1;
	}

	int	result	= 1;

// OTX_CLI is defined in the CLI target settings. Much thanx to Slava Karpenko
// and Mike Solomon for telling me about the -D flag.
#ifdef OTX_CLI

	NSAutoreleasePool*	pool		= [[NSAutoreleasePool alloc] init];
	CLIController*		controller	=
		[[CLIController alloc] initWithArgs: argv count: argc];

	if (controller)
	{
		[controller processFile];
		[controller release];

		result	= noErr;
	}
	else
		result	= -1;

	[pool release];

#else

	result	= NSApplicationMain(argc, (const char**)argv);

#endif

	return result;
}
