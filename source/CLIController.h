/*
	CLIController.h

	This file is in the public domain.
*/

#import "SharedDefs.h"
#import "ProgressReporter.h"

// ============================================================================

@interface CLIController : NSObject<ProgressReporter>
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
- (SInt32)checkOtool;

- (void)processFile;
- (void)verifyNops;
- (void)newPackageFile: (NSURL*)inPackageFile;
- (void)newOFile: (NSURL*)inOFile
	   needsPath: (BOOL)inNeedsPath;

// alerts
- (void)doErrorAlert;

@end
