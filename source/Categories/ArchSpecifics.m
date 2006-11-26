/*
	ArchSpecifics.m


*/

#import "ArchSpecifics.h"

@implementation ExeProcessor (ArchSpecifics)

//	gatherFuncInfos
// ----------------------------------------------------------------------------
//	Subclasses may override

- (void)gatherFuncInfos
{}

//	postProcessCodeLine:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)postProcessCodeLine: (Line**)ioLine
{}

//	lineIsFunction:
// ----------------------------------------------------------------------------
//	Subclasses may override

- (BOOL)lineIsFunction: (Line*)inLine
{
	return false;
}

//	chooseLine:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)chooseLine: (Line**)ioLine
{}

//	codeFromLine:
// ----------------------------------------------------------------------------
//	Subclasses must override.

- (void)codeFromLine: (Line*)inLine
{}

//	checkThunk:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)checkThunk:(Line*)inLine
{}

//	commentForLine:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)commentForLine: (Line*)inLine
{}

//	commentForSystemCall
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)commentForSystemCall
{}

//	commentForMsgSend:fromLine:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)commentForMsgSend: (char*)ioComment
				 fromLine: (Line*)inLine
{}

//	selectorForMsgSend:fromLine:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (char*)selectorForMsgSend: (char*)ioComment
				   fromLine: (Line*)inLine
{
	return nil;
}

#pragma mark -
//	resetRegisters:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)resetRegisters: (Line*)inLine
{}

//	updateRegisters:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (void)updateRegisters: (Line*)inLine
{}

//	restoreRegisters:
// ----------------------------------------------------------------------------
//	Subclasses may override.

- (BOOL)restoreRegisters: (Line*)ioLine
{
	return false;
}

@end
