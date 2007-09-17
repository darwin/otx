/*
	CLIController.h

	This file is in the public domain.
*/

#import "SharedDefs.h"
#import "ErrorReporter.h"
#import "ProgressReporter.h"

// Default ProcOptions values
#define	SHOW_LOCAL_OFFSETS				true
#define	DONT_ENTAB_OUTPUT				false
#define	DONT_SHOW_DATA_SECTIONS			false
#define	SHOW_CHECKSUM					true
#define	SHOW_VERBOSE_MSGSENDS			true
#define	DONT_SEPARATE_LOGICAL_BLOCKS	false
#define	DEMANGLE_CPP_NAMES				true
#define	SHOW_METHOD_RETURN_TYPES		true
#define	SHOW_VARIABLE_TYPES				true

// ============================================================================

@interface CLIController : NSObject<ProgressReporter, ErrorReporter>
{
@private
	NSURL*				mOFile;
	char*				mRAMFile;
	cpu_type_t			mArchSelector;
	UInt32				mArchMagic;
	BOOL				mFileIsValid;
	BOOL				mIgnoreArch;
	NSString*			mExeName;
	BOOL				mVerify;
	BOOL				mShowProgress;
	ProcOptions			mOpts;
}

- (id)initWithArgs: (char**)argv
			 count: (SInt32)argc;
- (void)initSCR;

- (void)usage;

- (void)processFile;
- (void)verifyNops;
- (void)newPackageFile: (NSURL*)inPackageFile;
- (void)newOFile: (NSURL*)inOFile
	   needsPath: (BOOL)inNeedsPath;

@end
