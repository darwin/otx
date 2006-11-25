/*
	ProgressReporter.h
*/

typedef struct
{
	BOOL		setIndeterminate;
	BOOL		indeterminate;
	UInt32		refcon;			// i'm bringing back refcons!
	double*		value;
	NSString*	description;
}
ProgressState;

@protocol	ProgressReporter

- (void)reportProgress: (ProgressState*)inState;

@end
