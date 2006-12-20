/*
	ListUtils.h

	A category on ExeProcessor that contains the linked list
	manipulation methods.

	This file is in the pubic domain.
*/

#import "ExeProcessor.h"

@interface	ExeProcessor (ListUtils)

- (void)insertLine: (Line*)inLine
			before: (Line*)nextLine
			inList: (Line**)listHead;
- (void)insertLine: (Line*)inLine
			 after: (Line*)prevLine
			inList: (Line**)listHead;
- (void)replaceLine: (Line*)inLine
		   withLine: (Line*)newLine
			 inList: (Line**)listHead;
- (BOOL)printLinesFromList: (Line*)listHead;
- (void)deleteLinesFromList: (Line*)listHead;

@end
