/*
	ProgressReporter.h

	This file is in the public domain.
*/

#define	PRIndeterminateKey	@"PRIndeterminateKey"	// NSNumber* (BOOL)
#define	PRValueKey			@"PRValueKey"			// NSNumber* (double)
#define	PRNewLineKey		@"PRNewLineKey"			// NSNull*	// I out-slicked myself...
#define PRAnimateKey		@"PRAnimateKey"			// NSNull*	//  change these to BOOLs
#define PRCompleteKey		@"PRCompleteKey"		// NSNull*	//  for readability.
#define	PRDescriptionKey	@"PRDescriptionKey"		// NSString*

@protocol	ProgressReporter

- (void)reportProgress: (NSDictionary*)inState;

@end
