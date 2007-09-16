/*
	SysUtils.m

	This file is in the public domain.
*/

#import "SystemIncludes.h"	// for UTF8STRING()
#import "SysUtils.h"

@implementation NSObject(SysUtils)

//	checkOtool
// ----------------------------------------------------------------------------

- (SInt32)checkOtool: (NSString*)filePath
{
	NSString*	otoolString	= [NSString stringWithFormat:
		@"otool -h \"%@\" > /dev/null", filePath];    

	return system(UTF8STRING(otoolString));
}

@end
