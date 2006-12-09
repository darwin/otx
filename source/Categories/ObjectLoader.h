/*
	ObjectLoader.h

	A category on ExeProcessor that contains all the loadXXX methods.
*/

#import "ExeProcessor.h"

@interface	ExeProcessor (ObjectLoader)

- (BOOL)loadMachHeader;
- (void)loadLCommands;
- (void)loadSegment: (segment_command*)inSegPtr;
//- (void)loadObjectSegment: (segment_command*)inSegPtr;
- (void)loadSymbols: (symtab_command*)inSymPtr;
- (void)loadDySymbols: (dysymtab_command*)inSymPtr;
- (void)loadObjcSection: (section*)inSect;
- (void)loadObjcModules;
- (void)loadCStringSection: (section*)inSect;
- (void)loadNSStringSection: (section*)inSect;
- (void)loadClassSection: (section*)inSect;
- (void)loadMetaClassSection: (section*)inSect;
- (void)loadIVarSection: (section*)inSect;
- (void)loadObjcModSection: (section*)inSect;
- (void)loadObjcSymSection: (section*)inSect;
- (void)loadLit4Section: (section*)inSect;
- (void)loadLit8Section: (section*)inSect;
- (void)loadTextSection: (section*)inSect;
- (void)loadCoalTextSection: (section*)inSect;
- (void)loadCoalTextNTSection: (section*)inSect;
- (void)loadConstTextSection: (section*)inSect;
- (void)loadDataSection: (section*)inSect;
- (void)loadCoalDataSection: (section*)inSect;
- (void)loadCoalDataNTSection: (section*)inSect;
- (void)loadConstDataSection: (section*)inSect;
- (void)loadDyldDataSection: (section*)inSect;
- (void)loadCFStringSection: (section*)inSect;
- (void)loadNonLazySymbolSection: (section*)inSect;
- (void)loadImpPtrSection: (section*)inSect;

@end
