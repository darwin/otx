/*
	ArchSpecifics.m

	A category on ExeProcessor that contains most of the
	architecture-specific methods.
*/

#import "ArchSpecifics.h"

@implementation ExeProcessor (ArchSpecifics)

//	gatherFuncInfos
// ----------------------------------------------------------------------------

- (void)gatherFuncInfos
{}

//	postProcessCodeLine:
// ----------------------------------------------------------------------------

- (void)postProcessCodeLine: (Line**)ioLine
{}

//	lineIsFunction:
// ----------------------------------------------------------------------------

- (BOOL)lineIsFunction: (Line*)inLine
{
	return false;
}

//	codeFromLine:
// ----------------------------------------------------------------------------

- (void)codeFromLine: (Line*)inLine
{}

//	checkThunk:
// ----------------------------------------------------------------------------

- (void)checkThunk:(Line*)inLine
{}

//	getThunkInfo:forLine:
// ----------------------------------------------------------------------------

- (BOOL)getThunkInfo: (ThunkInfo*)outInfo
			 forLine: (Line*)inLine
{
	return false;
}

#pragma mark -
//	commentForLine:
// ----------------------------------------------------------------------------

- (void)commentForLine: (Line*)inLine
{}

//	commentForSystemCall
// ----------------------------------------------------------------------------

- (void)commentForSystemCall
{}

//	commentForMsgSend:fromLine:
// ----------------------------------------------------------------------------

- (void)commentForMsgSend: (char*)ioComment
				 fromLine: (Line*)inLine
{}

#pragma mark -
//	resetRegisters:
// ----------------------------------------------------------------------------

- (void)resetRegisters: (Line*)inLine
{}

//	updateRegisters:
// ----------------------------------------------------------------------------

- (void)updateRegisters: (Line*)inLine
{}

//	restoreRegisters:
// ----------------------------------------------------------------------------

- (BOOL)restoreRegisters: (Line*)ioLine
{
	return false;
}

@end
