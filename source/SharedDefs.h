/*
	SharedDefs.h

	Definitions shared by GUI and CLI versions.

	This file is in the public domain.
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

// Default ProcOptions values
#define	SHOW_LOCAL_OFFSETS				true
#define ENTAB_OUTPUT					true
#define DONT_SHOW_DATA_SECTIONS			false
#define SHOW_CHECKSUM					true
#define SHOW_VERBOSE_MSGSENDS			true
#define DONT_SEPARATE_LOGICAL_BLOCKS	false
#define DEMANGLE_CPP_NAMES				true
#define SHOW_METHOD_RETURN_TYPES		true
#define SHOW_VARIABLE_TYPES				true
