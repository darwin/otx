/*
	Deobfuscator.h
*/

@protocol	Deobfuscator

- (BOOL)verifyNops: (unsigned char***)outList
		  numFound: (UInt32*)outFound;
- (unsigned char**)searchForNopsIn: (unsigned char*)inHaystack
						  ofLength: (UInt32)inHaystackLength
						  numFound: (UInt32*)outFound;
- (NSURL*)fixNops: (NopList*)inList
		   toPath: (NSString*)inOutputFilePath;

@end
