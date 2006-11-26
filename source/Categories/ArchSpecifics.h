/*
	ArchSpecifics.h

*/

#import "ExeProcessor.h"

@interface	ExeProcessor (ArchSpecifics)

- (void)gatherFuncInfos;
- (void)postProcessCodeLine: (Line**)ioLine;
- (BOOL)lineIsFunction: (Line*)inLine;
- (void)codeFromLine: (Line*)inLine;
- (void)checkThunk: (Line*)inLine;

- (void)commentForLine: (Line*)inLine;
- (void)commentForSystemCall;
- (void)commentForMsgSend: (char*)ioComment
				 fromLine: (Line*)inLine;
- (char*)selectorForMsgSend: (char*)ioComment
				   fromLine: (Line*)inLine;

- (void)chooseLine: (Line**)ioLine;

- (void)resetRegisters: (Line*)inLine;
- (void)updateRegisters: (Line*)inLine;
- (BOOL)restoreRegisters: (Line*)inLine;

@end
