/*
	ListUtils.m

	A category on ExeProcessor that contains the linked list
	manipulation methods.

	This file is in the pubic domain.
*/

#import "ListUtils.h"

@implementation ExeProcessor (ListUtils)

// Each text line is stored in one element of a doubly-linked list. These are
// vanilla textbook funcs for maintaining the list.

//	insertLine:before:inList:
// ----------------------------------------------------------------------------

- (void)insertLine: (Line*)inLine
			before: (Line*)nextLine
			inList: (Line**)listHead
{
	if (!nextLine)
		return;

	if (nextLine == *listHead)
		*listHead	= inLine;

	inLine->prev	= nextLine->prev;
	inLine->next	= nextLine;
	nextLine->prev	= inLine;

	if (inLine->prev)
		inLine->prev->next	= inLine;
}

//	insertLine:after:inList:
// ----------------------------------------------------------------------------

- (void)insertLine: (Line*)inLine
			 after: (Line*)prevLine
			inList: (Line**)listHead
{
	if (!prevLine)
	{
		*listHead	= inLine;
		return;
	}

	inLine->next	= prevLine->next;
	inLine->prev	= prevLine;
	prevLine->next	= inLine;

	if (inLine->next)
		inLine->next->prev	= inLine;
}

//	replaceLine:withLine:inList:
// ----------------------------------------------------------------------------

- (void)replaceLine: (Line*)inLine
		   withLine: (Line*)newLine
			 inList: (Line**)listHead
{
	if (!inLine || !newLine)
		return;

	if (inLine == *listHead)
		*listHead	= newLine;

	newLine->next	= inLine->next;
	newLine->prev	= inLine->prev;

	if (newLine->next)
		newLine->next->prev	= newLine;

	if (newLine->prev)
		newLine->prev->next	= newLine;

	if (inLine->chars)
		free(inLine->chars);

	free(inLine);
}

//	printLinesFromList:
// ----------------------------------------------------------------------------

- (BOOL)printLinesFromList: (Line*)listHead
{
	FILE*	outFile;

	if (mOutputFilePath)
	{
		const char*	outPath		= CSTRING(mOutputFilePath);
		outFile					= fopen(outPath, "w");
	}
	else
		outFile	= stdout;

	if (!outFile)
	{
		perror("otx: unable to open output file");
		return false;
	}

	Line*	theLine	= listHead;
	SInt32	fileNum	= fileno(outFile);

	while (theLine)
	{
		if (syscall(SYS_write, fileNum, theLine->chars, theLine->length) == -1)
		{
			perror("otx: unable to write to output file");

			if (mOutputFilePath)
			{
				if (fclose(outFile) != 0)
					perror("otx: unable to close output file");
			}

			return false;
		}

		theLine	= theLine->next;
	}

	if (mOutputFilePath)
	{
		if (fclose(outFile) != 0)
		{
			perror("otx: unable to close output file");
			return false;
		}
	}

	return true;
}

//	deleteLinesFromList:
// ----------------------------------------------------------------------------

- (void)deleteLinesFromList: (Line*)listHead;
{
	Line*	theLine	= listHead;

	while (theLine)
	{
		if (theLine->prev)				// if there's one behind us...
		{
			free(theLine->prev->chars);	// delete it
			free(theLine->prev);
		}

		if (theLine->next)				// if there are more...
			theLine	= theLine->next;	// jump to next one
		else
		{								// this is last one, delete it
			free(theLine->chars);
			free(theLine);
			theLine	= nil;
		}
	}
}

@end
