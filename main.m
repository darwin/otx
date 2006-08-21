#import <AppKit/NSApplication.h>
#import <Cocoa/Cocoa.h>

#ifndef NSAppKitVersionNumber10_4
#define NSAppKitVersionNumber10_4 824
#endif

int main(
	int		argc,
	char*	argv[])
{
	if (NSAppKitVersionNumber < floor(NSAppKitVersionNumber10_4))
		return noErr;

	return NSApplicationMain(argc, (const char**)argv);
}
