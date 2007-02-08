/*
	ProgressReporter.h

	This file is in the public domain.
*/

#define	PRIndeterminateKey	@"PRIndeterminateKey"	// NSNumber* (BOOL)
#define	PRValueKey			@"PRValueKey"			// NSNumber* (double)
#define	PRNewLineKey		@"PRNewLineKey"			// NSNull*
#define PRAnimateKey		@"PRAnimateKey"			// NSNull*
#define PRCompleteKey		@"PRCompleteKey"		// NSNull*
#define	PRDescriptionKey	@"PRDescriptionKey"		// NSString*

@protocol	ProgressReporter

- (void)reportProgress: (NSDictionary*)inState;

@end
