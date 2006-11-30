/*
	CLIController.h
*/

#import <Cocoa/Cocoa.h>

#import "ProgressReporter.h"

// ============================================================================

@interface CLIController : NSObject <ProgressReporter>
{
@private
	NSURL*				mOFile;
	char*				mRAMFile;
	cpu_type_t			mArchSelector;
	UInt32				mArchMagic;
	BOOL				mExeIsFat;
	BOOL				mFileIsValid;
	BOOL				mIgnoreArch;
	NSString*			mExeName;
	BOOL				mVerify;
	BOOL				mShowProgress;

	ProcOptions			mOpts;
}

- (id)initWithArgs: (char**) argv
			 count: (SInt32) argc;

- (void)usage;
- (SInt32)checkOtool;

- (IBAction)processFile: (id)sender;
- (IBAction)verifyNops: (id)sender;
- (void)newPackageFile: (NSURL*)inPackageFile;
- (void)newOFile: (NSURL*)inOFile
	   needsPath: (BOOL)inNeedsPath;

// alerts
- (void)doErrorAlert;
- (void)doDrillErrorAlert: (NSString*)inExePath;

// ProgressReporter protocol
- (void)reportProgress: (ProgressState*)inState;

@end
