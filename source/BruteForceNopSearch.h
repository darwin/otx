#import <Cocoa/Cocoa.h>

@interface BruteForceNopSearch	: NSObject
{}

- (UInt32*)searchIn: (unsigned char*)inHaystack
		   OfLength: (UInt32)inHaystackLength
		   NumFound: (UInt32*)outFound
	OnlyByExistence: (BOOL)inByExistence;

@end
