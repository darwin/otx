/*
	ProgressReporter.h

	This file is in the public domain.
*/

#define	PRValueKey			@"PRValueKey"			// NSNumber* (double)
#define	PRIndeterminateKey	@"PRIndeterminateKey"	// NSNumber* (BOOL)
#define	PRNewLineKey		@"PRNewLineKey"			// NSNumber* (BOOL)
#define PRAnimateKey		@"PRAnimateKey"			// NSNumber* (BOOL)
#define PRCompleteKey		@"PRCompleteKey"		// NSNumber* (BOOL)
#define	PRDescriptionKey	@"PRDescriptionKey"		// NSString*

@protocol	ProgressReporter

- (void)reportProgress: (NSDictionary*)inState;

@end
