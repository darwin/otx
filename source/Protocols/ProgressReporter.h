/*
	ProgressReporter.h

	This file is in the public domain.
*/

#define	PRIndeterminateKey	@"PRIndeterminateKey"	// NSNumber* (BOOL)
#define	PRValueKey			@"PRValueKey"			// NSNumber* (double)
#define	PRNewLineKey		@"PRNewLineKey"			// NSNumber* (BOOL)
#define	PRRefconKey			@"PRRefconKey"			// NSNumber* (UInt32)
#define	PRDescriptionKey	@"PRDescriptionKey"		// NSString*

// Constants to indicate various stages of processing
enum {
	Nudge,
	GeneratingFile,
	Complete
};

@protocol	ProgressReporter

- (void)reportProgress: (NSDictionary*)inState;

@end
