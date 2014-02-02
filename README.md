#otx

**otool's bastard son**

Original Author: **otx at osxninja dot com**
## wtf is otx?

otx stands for "object tool extended". It uses otool (object tool) to disassemble a Mach-O executable file, then enhances the disassembled output. Simple enhancements include adding the machine code of each instruction and the offset of each instruction from the beginning of a function. More complicated enhancements include displaying the names and data types of Objective-C methods even if symbols have been stripped, and adding comments that describe member variables, function calls, static data and more.

otx users should have Apple's developer tools installed. The otx distribution includes both a GUI application and a command line utility, for your convenience. You can use either or both, as you see fit.
