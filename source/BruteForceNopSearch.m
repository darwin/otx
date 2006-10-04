#import "BruteForceNopSearch.h"

@implementation BruteForceNopSearch

//	searchIn:OfLength:NumFound:OnlyByExistence:
// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

- (UInt32*)searchIn: (unsigned char*)inHaystack
		   OfLength: (UInt32)inHaystackLength
		   NumFound: (UInt32*)outFound
	OnlyByExistence: (BOOL)inByExistence;
{
	UInt32*			foundList			= nil;
	unsigned char	theSearchString[4]	= {0x00, 0x55, 0x89, 0xe5};
	unsigned char*	current;

	*outFound	= 0;

	// loop thru haystack
	for (current = inHaystack;
		 current <= inHaystack + inHaystackLength - 4;
		 current++)
	{
		if (memcmp(current, theSearchString, 4) != 0)
			continue;

		// Match for common benign occurences
		if (*(current - 4) == 0xe9	||	// jmpl
			*(current - 2) == 0xc2)		// ret
			continue;

		// Match for common malignant occurences
		if (*(current - 7) != 0xe9	&&	// jmpl
			*(current - 5) != 0xe9	&&	// jmpl
			*(current - 4) != 0xeb	&&	// jmp
			*(current - 2) != 0xeb	&&	// jmp
			*(current - 5) != 0xc2	&&	// ret
			*(current - 5) != 0xca	&&	// ret
			*(current - 3) != 0xc3	&&	// ret
			*(current - 3) != 0xcb	&&	// ret
			*(current - 1) != 0xc3	&&	// ret
			*(current - 1) != 0xcb)		// ret
			continue;

		(*outFound)++;

		if (foundList)
			foundList	= realloc(foundList, *outFound * sizeof(UInt32));
		else
			foundList	= malloc(sizeof(UInt32));

		foundList[*outFound - 1]	= (UInt32)current;
	}

	return foundList;
}

@end
