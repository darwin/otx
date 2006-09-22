// Definitions stolen from, or inspired by, darwin & cctools.
#define rotr(x, n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rotl(x, n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))

// section_t is defined in cctools-590/include/stuff/target_arch.h as either
// section or section_64. We don't play with 64 yet.
typedef struct
{
//	section_t		s;
	section			s;
	char*			contents;
	unsigned long	size;
}
section_info;

// NSString, from cctools-590/otool/print_objc.c, alternate definition in
// http://www.opensource.apple.com/darwinsource/10.4.7.ppc/objc4-267.1/runtime/objc-private.h
typedef struct
{
	objc_class*		isa;
	char*			chars;
	unsigned int	length;
}
objc_string_object;

// CFString
typedef struct
{
	UInt32				isa;
	objc_string_object	oc;
}
cf_string_object;

// The isa field of an NSString is 0x7c8 (1992) when it exists in the
// (__DATA,__const) section. This makes it possible to identify both
// NSString's and CFString's. I can't find any documentation about the
// 1992 date, but it is assumed to be the date of birth of NSStrings.
#define typeid_NSString		0x000007c8
