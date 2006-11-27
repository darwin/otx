/*
	ProgressReporter.h
*/

typedef struct
{
	BOOL		setIndeterminate;
	BOOL		indeterminate;
	BOOL		newLine;		// prepend \n in CLI version
	UInt32		refcon;
	double*		value;
	NSString*	description;
}
ProgressState;

@protocol	ProgressReporter

- (void)reportProgress: (ProgressState*)inState;

@end
