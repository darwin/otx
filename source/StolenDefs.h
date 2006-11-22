/*
	StolenDefs.h

	Definitions stolen from, or inspired by, Darwin & cctools.
*/

//#import <mach-o/loader.h>

#define rotr(x, n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rotl(x, n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))

/*	section_info

	section_t is defined in cctools-590/include/stuff/target_arch.h as either
	section or section_64. We don't play with 64 yet.
*/
typedef struct
{
//	section_t		s;
	section			s;
	char*			contents;
	unsigned long	size;
}
section_info;

/*	dyld_data_section

	Adapted from
	http://www.opensource.apple.com/darwinsource/10.4.7.ppc/cctools-590.23.6/libdyld/debug.h
*/
typedef struct
{
	void*			stub_binding_helper_interface;
	void*			_dyld_func_lookup;
	void*			start_debug_thread;
	mach_port_t		debug_port;
	thread_port_t	debug_thread;
	void*			dyld_stub_binding_helper;
//	unsigned long	core_debug;	// wrong size and ignored by us anyway
}
dyld_data_section;

/*	NSString

	From cctools-590/otool/print_objc.c, alternate definition in
	http://www.opensource.apple.com/darwinsource/10.4.7.ppc/objc4-267.1/runtime/objc-private.h
*/
typedef struct
{
	objc_class*		isa;
	char*			chars;
	unsigned int	length;
}
objc_string_object;

/*	CFString

	The only piece of reverse-engineered data in otx. I was unable to find any
	documentation about the structure of CFStrings, but they appear to be
	NSStrings with an extra data member prepended. Following NSString's lead,
	i'm calling it 'isa'. The observed values of 'isa' change from app to app,
	but remain constant in each app. A little gdb effort could probably shed
	some light on what they actually point to, but otx has nothing to gain from
	that knowledge. Still, any feedback regarding this issue is most welcome.
*/
typedef struct
{
	UInt32				isa;
	objc_string_object	oc_string;
}
cf_string_object;

/*	The isa field of an NSString is 0x7c8 (1992) when it exists in the
	(__DATA,__const) section. This makes it possible to identify both
	NSString's and CFString's. I can't find any documentation about the
	1992 date, but it is assumed to be the date of birth of NSStrings.
*/
#define typeid_NSString		0x000007c8
