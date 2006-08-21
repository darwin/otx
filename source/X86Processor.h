#import "ExeProcessor.h"

// Addressing modes in mod field of mod r/m byte
#define MODimm	0
#define MOD8	1
#define MOD32	2

#define DISP32	5

// Register identifiers in r/m field of mod r/m byte
enum {
	NOREG	= -1,
	EAX,	// 0
	ECX,	// 1
	EDX,	// 2
	EBX,	// 3
	ESP,	// 4
	EBP,	// 5
	ESI,	// 6
	EDI		// 7
};

// Macros for various ugly x86 data
#define LO(x)			((x) & 0xf)				// bits 0-3
#define HI(x)			(((x) >> 4) & 0xf)		// bits 4-7
//#define DIR(x)			(((x) >> 1) & 0x1)		// bit 1
#define MOD(x)			(((x) >> 6) & 0x3)		// bits 6-7
#define REG1(x)			(((x) >> 3) & 0x7)		// bits 3-5
#define REG2(x)			((x) & 0x7)				// bits 0-2
#define OPEXT(x)		REG1((x))
#define RM(x)			REG2((x))
#define HAS_SIB(x)		(MOD((x)) < 0x3 && REG2((x)) == 0x4)
#define HAS_DISP8(x)	(MOD((x)) == MOD8)

// ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

@interface X86Processor : ExeProcessor
{
	RegisterInfo	mRegInfos[8];
}

@end
