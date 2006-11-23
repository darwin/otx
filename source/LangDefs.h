/*
	LangDefs.h
*/

// I refuse to type 'struct' 1,000 times.
#define fat_header			struct fat_header
#define fat_arch			struct fat_arch
#define mach_header			struct mach_header
#define load_command		struct load_command
#define segment_command		struct segment_command
#define symtab_command		struct symtab_command
#define dysymtab_command	struct dysymtab_command
#define nlist				struct nlist
#define section				struct section
#define objc_module			struct objc_module
#define objc_symtab			struct objc_symtab
#define objc_class			struct objc_class
#define objc_ivar_list		struct objc_ivar_list
#define objc_ivar			struct objc_ivar
#define objc_method_list	struct objc_method_list
#define objc_method			struct objc_method
#define objc_cache			struct objc_cache
#define objc_category		struct objc_category
#define objc_protocol_list	struct objc_protocol_list

// why not
#define CSTRING(s)	[(s) cStringUsingEncoding: NSMacOSRomanStringEncoding]
#define NSSTRING(s)	\
	[NSString stringWithCString: (s) encoding: NSMacOSRomanStringEncoding]
