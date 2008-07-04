/*
    Deobfuscator.h

    This file is in the public domain.
*/

#import <Cocoa/Cocoa.h>

/*  NopList

    'list' is a 'count'-sized array of addresses at which an obfuscated
    sequence of nops was found.
*/
typedef struct NopList
{
    unsigned char** list;
    UInt32          count;
}
NopList;

// ============================================================================

@protocol Deobfuscator

- (BOOL)verifyNops: (unsigned char***)outList
          numFound: (UInt32*)outFound;
- (unsigned char**)searchForNopsIn: (unsigned char*)inHaystack
                          ofLength: (UInt32)inHaystackLength
                          numFound: (UInt32*)outFound;
- (NSURL*)fixNops: (NopList*)inList
           toPath: (NSString*)inOutputFilePath;

@end
