/*
	SharedDefs.h

	Definitions shared by GUI and CLI versions.

	This file is in the pubic domain.
*/

/*	ProcOptions

	Options for processing executables. GUI version sets these using
	NSUserDefaults, CLI version sets them with command line arguments. This
	is necessary for the CLI version to behave consistently across
	invocations, and to keep it from altering the GUI version's prefs.
*/
typedef struct
{
 	BOOL	localOffsets;			// l
 	BOOL	entabOutput;			// e
 	BOOL	dataSections;			// d
 	BOOL	checksum;				// c
 	BOOL	verboseMsgSends;		// m
 	BOOL	separateLogicalBlocks;	// b
 	BOOL	demangleCppNames;		// n
 	BOOL	returnTypes;			// r
 	BOOL	variableTypes;			// v
}
ProcOptions;
