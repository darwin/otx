/*
	SmarterPopen.m
 
	SmarterPopen ObjC bridge to popen()
 
	This file is in the public domain.
 */

#import "SmarterPopen.h"
#import <sys/syscall.h>

#ifdef USESMARTERPOPEN

@implementation SmarterPopen


- (BOOL)openPipe: (NSString*)inCode
{
    bool            ret_boolValue = true;
    
    FILE*           pFile_outfile = NULL;
    FILE*           pFile_errfile = NULL;
    
    const int       BUFFER_MAX_SIZE = 2000;
    char            buf [BUFFER_MAX_SIZE];
    
    const int       intDesc_STDERR = 2;
    int             intDesc_errfile;
    int             intDesc_new_errfile;
    int             intDesc_save_error;
    
    NSString *cur_string = @"";
    NSString *eol_string = @"\n";
    
    if ((pFile_errfile = tmpfile ()) == NULL)
        return false;
    
    intDesc_save_error = dup(intDesc_STDERR);
    
    if (!intDesc_save_error)
        return false;
    
    
    if (close (intDesc_STDERR) == -1)
        return false;    
    
    
     intDesc_new_errfile = dup (intDesc_errfile);
    if (!intDesc_new_errfile)
        return false;
    
    
    
    //pFile_outfile = popen( CSTRING(inCode), "r");
    pFile_outfile = popen("echo hello", "r");                  
    if (!pFile_outfile)
        return false;
    
    if (ret_boolValue)
    {
        while (fgets(buf, sizeof (buf), pFile_outfile))
        {
            cur_string =[NSString stringWithCString: buf
                                           encoding: NSMacOSRomanStringEncoding];
            
            if ( ![[cur_string substringFromIndex:1] compare:eol_string] )
            {
                ret_boolValue = false;
                break;
            }
                
        } 
        
        // ================================
        if (pclose(pFile_outfile) == -1)
        {
            ret_boolValue = false;
        }
     } // if (ret_boolValue)

    
    return ret_boolValue;
//    // ===================
}    
    
@end

#endif // USESMARTERPOPEN
