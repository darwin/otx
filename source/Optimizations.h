/*
	Optimizations.h

	Definitions of function types and selectors for use with
	getMethodForSelector: in ExeProcessor.
*/

// Function types
#define GetDescriptionFuncType					(void	(*)(id, SEL, char*, const char*))
#define LineIsCodeFuncType						(BOOL	(*)(id, SEL, const char*))
#define LineIsFunctionFuncType					(BOOL	(*)(id, SEL, Line*))
#define AddressFromLineFuncType					(UInt32	(*)(id, SEL, const char*))
#define CodeFromLineFuncType					(void	(*)(id, SEL, Line*))
#define CheckThunkFuncType						(void	(*)(id, SEL, Line*))
#define ProcessLineFuncType						(void	(*)(id, SEL, Line*))
#define ProcessCodeLineFuncType					(void	(*)(id, SEL, Line**))
#define PostProcessCodeLineFuncType				(void	(*)(id, SEL, Line**))
#define ChooseLineFuncType						(void	(*)(id, SEL, Line**))
#define EntabLineFuncType						(void	(*)(id, SEL, Line*))
#define GetPointerFuncType						(char*	(*)(id, SEL, UInt32, UInt8*))
#define CommentForLineFuncType					(void	(*)(id, SEL, Line*))
#define CommentForSystemCallFuncType			(void	(*)(id, SEL))
#define CommentForMsgSendFromLineFuncType		(void	(*)(id, SEL, char*, Line*))
#define SelectorForMsgSendFuncType				(char*	(*)(id, SEL, char*, Line*))
#define SelectorIsFriendlyFuncType				(BOOL	(*)(id, SEL, const char*))
#define SendTypeFromMsgSendFuncType				(UInt8	(*)(id, SEL, char*))
#define ResetRegistersFuncType					(void	(*)(id, SEL, Line*))
#define UpdateRegistersFuncType					(void	(*)(id, SEL, Line*))
#define RestoreRegistersFuncType				(BOOL	(*)(id, SEL, Line*))
#define PrepareNameForDemanglingFuncType		(char*	(*)(id, SEL, char*))
#define GetObjcClassPtrFromMethodFuncType		(BOOL	(*)(id, SEL, objc_class**, UInt32))
#define GetObjcCatPtrFromMethodFuncType			(BOOL	(*)(id, SEL, objc_category**, UInt32))
#define GetObjcMethodFromAddressFuncType		(BOOL	(*)(id, SEL, MethodInfo**, UInt32))
#define GetObjcClassFromNameFuncType			(BOOL	(*)(id, SEL, objc_class*, const char*))
#define GetObjcDescriptionFromObjectFuncType	(BOOL	(*)(id, SEL, char**, const char*, UInt8))
#define InsertLineBeforeFuncType				(void	(*)(id, SEL, Line*, Line*, Line**))
#define InsertLineAfterFuncType					(void	(*)(id, SEL, Line*, Line*, Line**))
#define ReplaceLineFuncType						(void	(*)(id, SEL, Line*, Line*, Line**))
#define FindSymbolByAddressFuncType				(BOOL	(*)(id, SEL, UInt32))
//#define FindDySymbolByAddressFuncType			(BOOL	(*)(id, SEL, UInt32))
#define FindClassMethodByAddressFuncType		(BOOL	(*)(id, SEL, MethodInfo**, UInt32))
#define FindCatMethodByAddressFuncType			(BOOL	(*)(id, SEL, MethodInfo**, UInt32))
#define FindIvarFuncType						(BOOL	(*)(id, SEL, objc_ivar*, objc_class*, UInt32))

// Selectors
#define GetDescriptionSel				@selector(getDescription:forType:)
#define LineIsCodeSel					@selector(lineIsCode:)
#define LineIsFunctionSel				@selector(lineIsFunction:)
#define AddressFromLineSel				@selector(addressFromLine:)
#define CodeFromLineSel					@selector(codeFromLine:)
#define CheckThunkSel					@selector(checkThunk:)
#define ProcessLineSel					@selector(processLine:)
#define ProcessCodeLineSel				@selector(processCodeLine:)
#define PostProcessCodeLineSel			@selector(postProcessCodeLine:)
#define ChooseLineSel					@selector(chooseLine:)
#define EntabLineSel					@selector(entabLine:)
#define GetPointerSel					@selector(getPointer:andType:)
#define CommentForLineSel				@selector(commentForLine:)
#define CommentForSystemCallSel			@selector(commentForSystemCall)
#define CommentForMsgSendFromLineSel	@selector(commentForMsgSend:fromLine:)
#define SelectorForMsgSendSel			@selector(selectorForMsgSend:fromLine:)
#define SelectorIsFriendlySel			@selector(selectorIsFriendly:)
#define SendTypeFromMsgSendSel			@selector(sendTypeFromMsgSend:)
#define ResetRegistersSel				@selector(resetRegisters:)
#define UpdateRegistersSel				@selector(updateRegisters:)
#define RestoreRegistersSel				@selector(restoreRegisters:)
#define PrepareNameForDemanglingSel		@selector(prepareNameForDemangling:)
#define GetObjcClassPtrFromMethodSel	@selector(getObjcClassPtr:fromMethod:)
#define GetObjcCatPtrFromMethodSel		@selector(getObjcCatPtr:fromMethod:)
#define GetObjcMethodFromAddressSel		@selector(getObjcMethod:fromAddress:)
#define GetObjcClassFromNameSel			@selector(getObjcClass:fromName:)
#define GetObjcDescriptionFromObjectSel	@selector(getObjcDescription:fromObject:type:)
#define InsertLineBeforeSel				@selector(insertLine:before:inList:)
#define InsertLineAfterSel				@selector(insertLine:after:inList:)
#define ReplaceLineSel					@selector(replaceLine:withLine:inList:)
#define FindSymbolByAddressSel			@selector(findSymbolByAddress:)
//#define FindDySymbolByAddressSel		@selector(findDySymbolByAddress:)
#define FindClassMethodByAddressSel		@selector(findClassMethod:byAddress:)
#define FindCatMethodByAddressSel		@selector(findCatMethod:byAddress:)
#define FindIvarSel						@selector(findIvar:inClass:withOffset:)

// These are not really necessary, but all that "self" crap gets old.
#define GetDescription(a, b)													\
		GetDescription(self, GetDescriptionSel, (a), (b))
#define LineIsCode(a)															\
		LineIsCode(self, LineIsCodeSel, (a))
#define LineIsFunction(a)														\
		LineIsFunction(self, LineIsFunctionSel, (a))
#define AddressFromLine(a)														\
		AddressFromLine(self, AddressFromLineSel, (a))
#define CodeFromLine(a)															\
		CodeFromLine(self, CodeFromLineSel, (a))
#define CheckThunk(a)															\
		CheckThunk(self, CheckThunkSel, (a))
#define ProcessLine(a)															\
		ProcessLine(self, ProcessLineSel, (a))
#define ProcessCodeLine(a)														\
		ProcessCodeLine(self, ProcessCodeLineSel, (a))
#define PostProcessCodeLine(a)													\
		PostProcessCodeLine(self, PostProcessCodeLineSel, (a))
#define ChooseLine(a)															\
		ChooseLine(self, ChooseLineSel, (a))
#define EntabLine(a)															\
		EntabLine(self, EntabLineSel, (a))
#define GetPointer(a, b)														\
		GetPointer(self, GetPointerSel, (a), (b))
#define CommentForLine(a)														\
		CommentForLine(self, CommentForLineSel, (a))
#define CommentForSystemCall()													\
		CommentForSystemCall(self, CommentForSystemCallSel)
#define CommentForMsgSendFromLine(a, b)											\
		CommentForMsgSendFromLine(self, CommentForMsgSendFromLineSel, (a), (b))
#define SelectorForMsgSend(a, b)												\
		SelectorForMsgSend(self, SelectorForMsgSendSel, (a), (b))
#define SelectorIsFriendly(a)													\
		SelectorIsFriendly(self, SelectorIsFriendlySel, (a))
#define SendTypeFromMsgSend(a)													\
		SendTypeFromMsgSend(self, SendTypeFromMsgSendSel, (a))
#define ResetRegisters(a)														\
		ResetRegisters(self, ResetRegistersSel, (a))
#define UpdateRegisters(a)														\
		UpdateRegisters(self, UpdateRegistersSel, (a))
#define RestoreRegisters(a)														\
		RestoreRegisters(self, RestoreRegistersSel, (a))
#define PrepareNameForDemangling(a)												\
		PrepareNameForDemangling(self, PrepareNameForDemanglingSel, (a))
#define GetObjcClassPtrFromMethod(a, b)											\
		GetObjcClassPtrFromMethod(self, GetObjcClassPtrFromMethodSel, (a), (b))
#define GetObjcCatPtrFromMethod(a, b)											\
		GetObjcCatPtrFromMethod(self, GetObjcCatPtrFromMethodSel, (a), (b))
#define GetObjcMethodFromAddress(a, b)											\
		GetObjcMethodFromAddress(self, GetObjcMethodFromAddressSel, (a), (b))
#define GetObjcClassFromName(a, b)												\
		GetObjcClassFromName(self, GetObjcClassFromNameSel, (a), (b))
#define GetObjcDescriptionFromObject(a, b, c)									\
		GetObjcDescriptionFromObject(self, GetObjcDescriptionFromObjectSel, (a), (b), (c))
#define InsertLineBefore(a, b, c)												\
		InsertLineBefore(self, InsertLineBeforeSel, (a), (b), (c))
#define InsertLineAfter(a, b, c)												\
		InsertLineAfter(self, InsertLineAfterSel, (a), (b), (c))
#define ReplaceLine(a, b, c)													\
		ReplaceLine(self, ReplaceLineSel, (a), (b), (c))
#define FindSymbolByAddress(a)													\
		FindSymbolByAddress(self, FindSymbolByAddressSel, (a))
//#define FindDySymbolByAddress(a)												\
//		FindDySymbolByAddress(self, FindDySymbolByAddressSel, (a))
#define FindClassMethodByAddress(a, b)											\
		FindClassMethodByAddress(self, FindClassMethodByAddressSel, (a), (b))
#define FindCatMethodByAddress(a, b)											\
		FindCatMethodByAddress(self, FindCatMethodByAddressSel, (a), (b))
#define FindIvar(a, b, c)														\
		FindIvar(self, FindIvarSel, (a), (b), (c))
