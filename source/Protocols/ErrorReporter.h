/*
	ErrorReporter.h

	This file is in the public domain.
*/

@protocol ErrorReporter

- (void)reportError: (NSString*)inMessageText
		 suggestion: (NSString*)inInformativeText;

@end