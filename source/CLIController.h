/*
	CLIController.h
*/

#import <Cocoa/Cocoa.h>
//#import <Kernel/mach-o/loader.h>

#import "ProgressReporter.h"

//#define _OTX_CLI_	1

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
//	NSString*			mOutputFileLabel;
//	NSString*			mOutputFileName;
//	NSString*			mOutputFilePath;
//	NSView**			mPrefsViews;
//	UInt32				mPrefsCurrentViewIndex;
}

- (id)initWithArgs: (char**) argv
			 count: (SInt32) argc;

- (SInt32)checkOtool;

- (IBAction)processFile: (id)sender;
- (IBAction)verifyNops: (id)sender;
- (void)newPackageFile: (NSURL*)inPackageFile;
- (void)newOFile: (NSURL*)inOFile
	   needsPath: (BOOL)inNeedsPath;

- (void)nopAlertDidEnd: (NSAlert*)alert
			returnCode: (int)returnCode
		   contextInfo: (void*)contextInfo;

// alerts
- (void)doOtoolAlert;
- (void)doLipoAlert;
- (void)doErrorAlert;
- (void)doDrillErrorAlert: (NSString*)inExePath;

// ProgressReporter protocol
- (void)reportProgress: (ProgressState*)inState;

@end
