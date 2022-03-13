/* C-program file that contains the
   code for the function to check
   which fields of the executable have
   what values and what they represent.

   This functionionality of rpe64 checks the contents of the various fields of the
   given executable and interprets what those values represent based on the information
   provided in the Microsoft Documentation.  
 */  

/* Written by Ranit Barman as a part of the Academia Internship project under Tezpur University

   Main reference material used: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
 */

#include <stdlib.h>
#include "rpe64Header.h"

/* The following function is used to check the values for the different fields within the PE32/PE32+ image file
 * and output what they represent
 * It takes the executable passed to it by the main function as a character pointer argument
 * It returns nothing and simply displays strings in the standard output
 */
void ExecutableFieldValues(const char *exee)
{
    unsigned char buffer[2048]; //This buffer stores the contents of the given executable up to and including the PE File Header, and much more
                                // The value is 2048 in order to accomodate most image files that are of large size
    FILE *infile = fopen(exee, "rb");
    fread(&buffer, 8, 256, infile);  // Reads 2048 bytes of binary data from the start of the given executable file.
    fclose(infile);

    //Important fields of the DOS Header
    printf ("\nDOS Header: --\n\n");
    printf ("Magic Number: 0x%X%X  (%.2s)\n", *(buffer+1), *buffer, buffer);
    printf ("PE File Header offset(e_lfanew): 0x%X%X%X%X\n", *(buffer+63), *(buffer+62), *(buffer+61), *(buffer+60));
    unsigned char e_lfanewc[4] = {*(buffer+63), *(buffer+62), *(buffer+61), *(buffer+60)};
    uint32_t e_lfanew = HexToDec(e_lfanewc);    //Stores the PE File Header offset in decimal format 

    // PE File Header section starts from here
    // The contents of the PE File Header have been aligned to 8 bytes boundary
    printf ("\nPE File Header: --\n\n");
    
    /* This is the 4-byte Dword signature that identifies the given file as a PE executable file
     * It's the first part of the PE File Header
     */
    printf ("Signature: %s  (0x%X%X%X%X)\n\n", (buffer+e_lfanew), *(buffer+e_lfanew+1), *(buffer+e_lfanew), *(buffer+e_lfanew+2), *(buffer+3));
    // printf ("Signature: %s  (0x%X%X%X%X)\n\n", (buffer+128), *(buffer+129), *(buffer+128), *(buffer+130), *(buffer+131));

    /* Image File Header section starts from here
     * It's the second section within the PE File Header
     */
    printf ("Image File Header --\n");
    
    /* If-else stack for determining the Machine-type of the given executable
     * It's of size 2-bytes and is the first field within the Image File Header
     */ 
    /* Although there are a lot of machine types that are included in the Microsoft Documentation,
     * this program will check for only those that are relevant in today's times
     */
    if ((*(buffer+e_lfanew+4)==0x64) && (*(buffer+e_lfanew+5)==0x86))     //64-bit Intel/AMD microprocessors
        printf ("\nMachine: IMAGE_FILE_MACHINE_AMD64  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));
    else if ((*(buffer+e_lfanew+4)==0xC0) && (*(buffer+e_lfanew+5)==0x01))    //original ARM microprocessors
        printf ("\nIMAGE_FILE_MACHINE_ARM  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));
    else if ((*(buffer+e_lfanew+4)==0x64) && (*(buffer+e_lfanew+5)==0xAA))    //modern ARM 64-bit microprocessors
        printf ("\nIMAGE_FILE_MACHINE_ARM64  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));
    else if ((*(buffer+e_lfanew+4)==0xC4) && (*(buffer+e_lfanew+5)==0x01))    //ARM Thumb-2 little-endian microprocessors
        printf ("\nIMAGE_FILE_MACHINE_ARMNT  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));
    else if ((*(buffer+e_lfanew+4)==0xBC) && (*(buffer+e_lfanew+5)==0x0E))    //EFI byte code
        printf ("\nIMAGE_FILE_MACHINE_EBC  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));
    else if ((*(buffer+e_lfanew+4)==0x4C) && (*(buffer+e_lfanew+5)==0x01))    //Intel 386 or later processors, 32-bit 
        printf ("\nIMAGE_FILE_MACHINE_I386  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));
    else if ((*(buffer+e_lfanew+4)==0x00) && (*(buffer+e_lfanew+5)==0x02))    //Obsolete Intel Itanium processor family
        printf ("\nIMAGE_FILE_MACHINE_IA64  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));    
    else if ((*(buffer+e_lfanew+4)==0xF0) && (*(buffer+e_lfanew+5)==0x01))    //Power PC microprocessors
        printf ("\nIMAGE_FILE_MACHINE_POWERPC  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));
    else if ((*(buffer+e_lfanew+4)==0xF1) && (*(buffer+e_lfanew+5)==0x01))    //Power PC microprocessors with floating-point support
        printf ("\nIMAGE_FILE_MACHINE_POWERPCFP  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));
    else if ((*(buffer+e_lfanew+4)==0x32) && (*(buffer+e_lfanew+5)==0x50))    //RISC-V architecture with 32-bit address space 
        printf ("\nIMAGE_FILE_MACHINE_RISCV32  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));
    else if ((*(buffer+e_lfanew+4)==0x64) && (*(buffer+e_lfanew+5)==0x50))    //RISC-V architecture with 64-bit address space 
        printf ("\nIMAGE_FILE_MACHINE_RISCV64  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));
    else if ((*(buffer+e_lfanew+4)==0xC2) && (*(buffer+e_lfanew+5)==0x01))    //ARM Thumb architecture processors
        printf ("\nIMAGE_FILE_MACHINE_THUMB  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));
    else    //The content of this field is assumed to be applicable to any machine type 
        printf ("\nIMAGE_FILE_MACHINE_UNKNOWN  0x%X%X\n", *(buffer+e_lfanew+5), *(buffer+e_lfanew+4));

    /* This the NumberOfSections field of the PE File Header
     * It's the second field within the Image File Header and is of size 2-bytes
     * It indicates the size of the Section Table, which immediately follows the PE File Header
     */
    unsigned char NoSc[2] = {*(buffer+e_lfanew+7), *(buffer+e_lfanew+6)};
    uint16_t NoScn = HexToDec16(NoSc);
    printf ("Number of Sections: %u\n", NoScn);

    /* This is the TimeDateStamp field of the PE File header
     * It's the third field within the Image File Header and is of size 4-bytes
     * It's the the low 32 bits of the number of seconds since 00:00 January 1, 1970,
     * and indicates when the file was created
     * If it's 0 or 0xFFFFFFFF, then it doesn't represent a meaningful date/time
     */
    unsigned char dts[4] = {*(buffer+e_lfanew+11), *(buffer+e_lfanew+10), *(buffer+e_lfanew+9), *(buffer+e_lfanew+8)};
    uint32_t dtsn = HexToDec(dts);
    printf ("Date/time stamp: %u\n", dtsn);

    /* This is the PointerToSymbolTable field of the PE File Header.
     * It's the fourth field within the Image File Header and is of size 4-bytes
     * It's the offfset for the COFF Symbol Table. Its value is 0 if no COFF Symbol table is present
     */
    printf ("Symbol Table Offset: 0x%X%X%X%X\n", *(buffer+e_lfanew+15), *(buffer+e_lfanew+14), *(buffer+e_lfanew+13), *(buffer+e_lfanew+12));

    /* This is the NumberOfymbols field of the PE File Header
     * It's the fifth field within the Image File Header and is of size 4-bytes
     * It indicates the number of entries in the Symbol Table
     */
    unsigned char NoS[4] = {*(buffer+e_lfanew+19), *(buffer+e_lfanew+18), *(buffer+e_lfanew+17), *(buffer+e_lfanew+16)};
    uint32_t NoSn = HexToDec(NoS);
    printf ("Number of Symbols: %u\n", NoSn);

    /* This is the SizeOfOptionalHeader field of the PE File Header
     * It's the sixth field within the Image File Header and is of size 2-bytes
     * It gives the size of the Image Optional Header that immediately follows the Image File Header
     */
    unsigned char SoOH[2] = {*(buffer+e_lfanew+21), *(buffer+e_lfanew+20)};
    uint32_t SoOHn = HexToDec16(SoOH);
    printf ("Size of Optional Header: %u bytes\n", SoOHn);
    
    /* This is the Characteristics field of the PE File Header
     * It's the seventh and final field of the Image File Header and is of size 2-bytes
     * This field contains the flags that indicate the attributes of the given executable file
     */
    printf ("Characteristics: 0x%X%X  ", *(buffer+e_lfanew+23), *(buffer+e_lfanew+22));
    
    //Characteristic flags
    if ((*(buffer+e_lfanew+23) == 0x00) && (*(buffer+e_lfanew+22) == 0x01))
        printf ("IMAGE_FILE_RELOCS_STRIPPED\n\n");  // Indicates that the imsge file doesn't contain base relocations and must therefore be loaded at its preferred base address
                                                    // Reports loader error if base address isn't available
                                                    // Image only flag, available in Windows CE, Windows NT and later
    else if ((*(buffer+e_lfanew+23) == 0x00) && (*(buffer+e_lfanew+22) == 0x02))
        printf ("IMAGE_FILE_EXECUTABLE_IMAGE\n\n");     // Image only field that indicates that the image file is valid and can be run
                                                        // Indicates linker error if it's not set
    else if ((*(buffer+e_lfanew+23) == 0x00) && (*(buffer+e_lfanew+22) == 0x04))
        printf ("MAGE_FILE_LINE_NUMS_STRIPPED\n\n");    // Indicates that COFF line numbers have been removed 
                                                        // Deprecated flag, should be 0       
    else if ((*(buffer+e_lfanew+23) == 0x00) && (*(buffer+e_lfanew+22) == 0x08))
        printf ("IMAGE_FILE_LOCAL_SYMS_STRIPPED\n\n");  // Indicates that COFF symbol table entries for local symbols have been removed
                                                        // Deprecated flag, should be 0
    else if ((*(buffer+e_lfanew+23) == 0x00) && (*(buffer+e_lfanew+22) == 0x10))
        printf ("IMAGE_FILE_AGGRESSIVE_WS_TRIM\n\n");   // Obsolete flag. For Windows 2000 and later, it must be 0
                                                        // Aggresively trim working set
    else if ((*(buffer+e_lfanew+23) == 0x00) && (*(buffer+e_lfanew+22) == 0x20))
        printf ("IMAGE_FILE_LARGE_ADDRESS_ AWARE\n\n"); // Indicates that the application can handle addresses greater than 2GB 
    else if ((*(buffer+e_lfanew+23) == 0x00) && (*(buffer+e_lfanew+22) == 0x80))
        printf ("IMAGE_FILE_BYTES_REVERSED_LO\n\n");    // Indicates that the image file is Little Endian. Deprecated flag and should be 0
    else if ((*(buffer+e_lfanew+23) == 0x01) && (*(buffer+e_lfanew+22) == 0x00))
        printf ("IMAGE_FILE_32BIT_MACHINE\n\n");        // Indicates that the machine is based on a 32-bit word architecture
    else if ((*(buffer+e_lfanew+23) == 0x02) && (*(buffer+e_lfanew+22) == 0x00))
        printf ("IMAGE_FILE_DEBUG_STRIPPED\n\n");       // Indicates that debugging information has been removed from the image file
    else if ((*(buffer+e_lfanew+23) == 0x04) && (*(buffer+e_lfanew+22) == 0x00))
        printf ("IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP\n\n"); // Indicates that the image should be run from Swap file if it's on removable media
    else if ((*(buffer+e_lfanew+23) == 0x08) && (*(buffer+e_lfanew+22) == 0x00))
        printf ("IMAGE_FILE_NET_RUN_FROM_SWAP\n\n");    // Indicates that the image should be run from the Swap file if it's on network media
    else if ((*(buffer+e_lfanew+23) == 0x10) && (*(buffer+e_lfanew+22) == 0x00))
        printf ("IMAGE_FILE_SYSTEM\n\n");               // Indicates that the image file is a system file, and not a user program
    else if ((*(buffer+e_lfanew+23) == 0x20) && (*(buffer+e_lfanew+22) == 0x00))
        printf ("IMAGE_FILE_DLL\n\n");                  // Indicates that the image file is a dynamic-link library (DLL)
                                                        // DLLs are executable files without main function and hence can't be directly run
    else if ((*(buffer+e_lfanew+23) == 0x40) && (*(buffer+e_lfanew+22) == 0x00))
        printf ("IMAGE_FILE_UP_SYSTEM_ONLY\n\n");       // Indicates that the image file should be run only on a uniprocessor machine
    else if ((*(buffer+e_lfanew+23) == 0x80) && (*(buffer+e_lfanew+22) == 0x00))
        printf ("IMAGE_FILE_BYTES_REVERSED_HI\n\n");    // Indicates that the image file is Big Endian. Deprecated flag and should be 0
    else
        printf ("Flag value to be explored\n\n");

    /* Image Optional Header section starts from her
     * It's the third and final section within the PE File Header
     * and is used to provide information to the loader
     * It must be present in executable image files, but is generally absent in object files
     * It doesn't have a fixed size, and its size is given by the
     * SizeOfOptionalHeader field within the PE File Header
     */
    
    printf ("Image Optional Header --\n");
    uint32_t IOH = e_lfanew+24;     // Stores the offset of the Image Optional Header in decimal format

    /* The first eight fields, from Optional Header Magic Number to the BaseOfCode/BaseOfData fields,
     * are the standard fields that aren't Windows-specific, and are defined for every
     * executable image implementation of PE32/PE32+ files
     */

    /* Optional Header Magic Number
     * This is the first field within the Image Optional Header
     * It determines whether the image file is a PE32(32-bit) or PE32+(64-bit) executable
     */    
    unsigned char MN[2] = {*(buffer+IOH+1), *(buffer+IOH)};
    uint16_t MNn = HexToDec16(MN);      // This value will be used for checking if the file is PE32 file or PE32+ file
    if (MNn == 267)
        printf ("\nMagic Number: 0x20b (PE32+)\n");
    else if (MNn == 523)
        printf ("\nMagic Number: 0x10b (PE32)\n");

    //MajorLinkerVersion field gives the major version of the linker
    printf ("Major Linker Version: %d\n", *(buffer+IOH+2));

    //MinorLinkerVersion field gives the minor version of the linker
    printf ("Major Linker Version: %d\n", *(buffer+IOH+3));

    /* SizeOfCode field within the Image Optional Header
     * indicates the size of the code (.text) section
     */
    unsigned char SoC[4] = {*(buffer+IOH+7), *(buffer+IOH+6), *(buffer+IOH+5), *(buffer+IOH+4)};
    uint32_t SoCn = HexToDec(SoC);
    printf ("Size of .text section: %u bytes\n", SoCn);

    /* SizeOfInitializedData field within the Image Optional Header
     * indicates the size of the initialized data (.data) section
     */
    unsigned char SoID[4] = {*(buffer+IOH+11), *(buffer+IOH+10), *(buffer+IOH+9), *(buffer+IOH+8)};
    uint32_t SoIDn = HexToDec(SoID);
    printf ("Size of .data section: %u bytes\n", SoIDn);

    /* SizeOfUninitializedData field within the Image Optional Header
     * indicates the size of the uninitialized data (.bss) section
     */
    unsigned char SoUD[4] = {*(buffer+IOH+15), *(buffer+IOH+14), *(buffer+IOH+13), *(buffer+IOH+12)};
    uint32_t SoUDn = HexToDec(SoUD);
    printf ("Size of .bss section: %u bytes\n", SoUDn);

    /* AddressofEntryPoint field within the Image Optional Header
     * indicates the address of the entry point relative to the image base when the executable file is loaded into memory
     * For program images, this is the starting address when the file is loaded into memory
     * When no entry-point is present, like in DLLs, its value is 0
     */
    printf ("Address of Entrypoint: 0x%X%X%X%X\n", *(buffer+IOH+19), *(buffer+IOH+18), *(buffer+IOH+17), *(buffer+IOH+16));

    /* BaseOfCode field within the Image Optional Header
     * identifies the address of the .text section relative to the ImageBase
     * when it's loaded into memory
     */
    printf ("Address of .text section: 0x%X%X%X%X\n", *(buffer+IOH+23), *(buffer+IOH+22), *(buffer+IOH+21), *(buffer+IOH+20));

    /* BaseOfData field within the Image Optional Header
     * identifies the address of the .data section relative to the ImageBase
     * when it's loaded into memory
     * This field isn't present in PE32+(64-bit) executables
     */
    if (MNn == 267)
        printf ("Address of .data section: 0x%X%X%X%X\n", *(buffer+IOH+27), *(buffer+IOH+26), *(buffer+IOH+25), *(buffer+IOH+24));
    
    /* The following fields upto and not including the data directories are
     * Windows-specific fields that are required by the linker and loader in Windows
     */

    /* ImageBase field within the Image Optional Header
     * identifies the preferred address of the first byte of the image file when loaded into memory
     */
    if (MNn ==267)
        printf ("ImageBase: 0x%X%X%X%X\n", *(buffer+IOH+31), *(buffer+IOH+30), *(buffer+IOH+29), *(buffer+IOH+28));
    else
        printf ("ImageBase: 0x%X%X%X%X%X%X%X%X\n", *(buffer+IOH+31), *(buffer+IOH+30), *(buffer+IOH+29), *(buffer+IOH+28), *(buffer+IOH+27), *(buffer+IOH+26), *(buffer+IOH+25), *(buffer+IOH+24));

    /* SectionAlignment field within the Image Optional Header
     * identifies the alignment(in bytes) of sections when they are loaded into memory
     * It must be greater than or equal to FileAlignment 
     * with the default being the page size of the machine architecture
     */
    unsigned char SA[4] = {*(buffer+IOH+35), *(buffer+IOH+34), *(buffer+IOH+33), *(buffer+IOH+32)};
    uint32_t SAn = HexToDec(SA);
    printf ("Section Alignment: %u\n", SAn);

    /* FileAlignment field within the Image Optional Header
     * identifies the alignment factor(in bytes) used to align the raw data of sections in the image file
     * Its default value is 512. It must match Section Alignment if SA < architecture page size
     */
    unsigned char FA[4] = {*(buffer+IOH+39), *(buffer+IOH+38), *(buffer+IOH+37), *(buffer+IOH+36)};
    uint32_t FAn = HexToDec(FA);
    printf ("Alignment Factor: %u\n", FAn);

    //MajorOperatingSystemVersion field gives the major version number of the required OS
    unsigned char MOSV[2] = {*(buffer+IOH+41), *(buffer+IOH+40)};
    uint16_t MOSVn = HexToDec16(MOSV);
    printf ("Major Version of Required OS: %u\n", MOSVn);

    //MinorOperatingSystemVersion field gives the minor version number of the required OS
    unsigned char mOSV[2] = {*(buffer+IOH+43), *(buffer+IOH+42)};
    uint16_t mOSVn = HexToDec16(mOSV);
    printf ("Minor Version of Required OS: %u\n", mOSVn);

    //MajorImageVersion field gives the major version number of the image
    unsigned char MIV[2] = {*(buffer+IOH+45), *(buffer+IOH+44)};
    uint16_t MIVn = HexToDec16(MIV);
    printf ("Major Version of Image: %u\n", MIVn);

    //MinorImageVersion field gives the minor version of the image
    unsigned char mIV[2] = {*(buffer+IOH+47), *(buffer+IOH+46)};
    uint16_t mIVn = HexToDec16(mIV);
    printf ("Minor Version of Image: %u\n", mIVn);

    //MajorSubsystemVersion field gives the major version number of the subsystem
    unsigned char MSV[2] = {*(buffer+IOH+49), *(buffer+IOH+48)};
    uint16_t MSVn = HexToDec16(MSV);
    printf ("Major version of Subsystem: %u\n", MSVn);

    //MinorSubsystemVersion field gives the minor version number of the susbsystem
    unsigned char mSV[2] = {*(buffer+IOH+51), *(buffer+IOH+50)};
    uint16_t mSVn = HexToDec16(mSV);
    printf ("Minor version of the Subsystem: %u\n", mSVn);

    /* The SizeOfImage field within the Image Optional Header gives the
     * size(in bytes) of the entire image file, including all headers and sections, as the image is loaded in memory
     * It must be a multiple of SectionAlignment
     */
    unsigned char SoI[4] = {*(buffer+IOH+59), *(buffer+IOH+58), *(buffer+IOH+57), *(buffer+IOH+56)};
    uint32_t SoIn = HexToDec(SoI);
    printf ("Size of the image file: %u bytes\n", SoIn);

    /* The SizeOfHeaders field within the Image Optional Header gives the
     * combined size of the MS-DOS stub, the PE File Header, and the Section headers, 
     * rounded up to a multiple of FileAlignment
     */
    unsigned char SoH[4] = {*(buffer+IOH+63), *(buffer+IOH+62), *(buffer+IOH+61), *(buffer+IOH+60)};
    uint32_t SoHn = HexToDec(SoH);
    printf ("Size of the headers: %u bytes\n", SoHn);

    //Field for the CHECKSUM of the image file
    printf ("Checksum: 0x%X%X%X%X\n", *(buffer+IOH+67), *(buffer+IOH+66), *(buffer+IOH+65), *(buffer+IOH+64));

    //The Subsystem field gives the subsystem that is required to run the image file
    unsigned char sub[2] = {*(buffer+IOH+69), *(buffer+IOH+68)};
    uint16_t subn = HexToDec16(sub);
    printf ("Subsystem: %u  ", subn);

    //Subsystem values
    char subsystems[17][41] = {"IMAGE_SUBSYSTEM_UNKNOWN", "IMAGE_SUBSYSTEM_NATIVE", "IMAGE_SUBSYSTEM_WINDOWS_GUI", "IMAGE_SUBSYSTEM_WINDOWS_CUI ", "N/A",
                               "IMAGE_SUBSYSTEM_OS2_CUI", "N/A", "IMAGE_SUBSYSTEM_POSIX_CUI", "IMAGE_SUBSYSTEM_NATIVE_WINDOWS", "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
                               "IMAGE_SUBSYSTEM_EFI_APPLICATION", "IMAGE_SUBSYSTEM_EFI_BOOT_ SERVICE_DRIVER", "IMAGE_SUBSYSTEM_EFI_RUNTIME_ DRIVER",
                               "IMAGE_SUBSYSTEM_EFI_ROM", "IMAGE_SUBSYSTEM_XBOX", "N/A", "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION "};
    printf ("%s\n", subsystems[subn]);

    //DLL Characteristics field
    printf ("DLL Characteristics:  0x%X%X  ", *(buffer+IOH+71), *(buffer+IOH+70));

    //DLL Characteristics flags
    if ((*(buffer+IOH+71) == 0x00) && (*(buffer+IOH+70) == 0x20))
        printf ("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA\n");  // Indicates that the image file can handle high entropy 64-bit virtual address space
    else if ((*(buffer+IOH+71) == 0x00) && (*(buffer+IOH+70) == 0x40))
        printf ("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE\n");     // Indicates that DLL can be relocated at load time
    else if ((*(buffer+IOH+71) == 0x00) && (*(buffer+IOH+70) == 0x80))
        printf ("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY\n");  // Indicates that code integrity checks are enforced
    else if ((*(buffer+IOH+71) == 0x01) && (*(buffer+IOH+70) == 0x00))
        printf ("IMAGE_DLLCHARACTERISTICS_NX_COMPAT\n");        // Indicates that the image file is NX compatible
    else if ((*(buffer+IOH+71) == 0x02) && (*(buffer+IOH+70) == 0x00))
        printf ("IMAGE_DLLCHARACTERISTICS_ NO_ISOLATION\n");    // Indicates that the image file is isolation aware, but shouldn't be isolated
    else if ((*(buffer+IOH+71) == 0x04) && (*(buffer+IOH+70) == 0x00))
        printf ("IMAGE_DLLCHARACTERISTICS_ NO_SEH\n");          // Indicates that the image file doesn't use structured exception(SE) handling
    else if ((*(buffer+IOH+71) == 0x08) && (*(buffer+IOH+70) == 0x00))
        printf ("IMAGE_DLLCHARACTERISTICS_ NO_BIND\n");         // Indicates that the image file shouldn't be binded
    else if ((*(buffer+IOH+71) == 0x10) && (*(buffer+IOH+70) == 0x00))
        printf ("MAGE_DLLCHARACTERISTICS_APPCONTAINER\n");      // Indicates that the image file must be executed in an AppContainer
    else if ((*(buffer+IOH+71) == 0x20) && (*(buffer+IOH+70) == 0x00))
        printf ("IMAGE_DLLCHARACTERISTICS_ WDM_DRIVER\n");      // Indicates that the executable is a Windows-Driver-Model(WDM) driver
    else if ((*(buffer+IOH+71) == 0x40) && (*(buffer+IOH+70) == 0x00))
        printf ("IMAGE_DLLCHARACTERISTICS_GUARD_CF\n");         // Indicates that the image file supports control flow guard
    else if ((*(buffer+IOH+71) == 0x40) && (*(buffer+IOH+70) == 0x00))
        printf ("IMAGE_DLLCHARACTERISTICS_ TERMINAL_SERVER_AWARE\n");   // Indicates that the image file is aware of terminal server connection
    else
        printf ("Flag value to be explored\n");

    /* The SizeOfStackReserve field within the PE File Header
     * gives the memory(in bytes) of the stack that is to be reserved for the image file
     */
    if (MNn == 267)
    {
        unsigned char SoSR[4] = {*(buffer+IOH+75), *(buffer+IOH+74), *(buffer+IOH+73), *(buffer+IOH+72)};
        uint32_t SoSRn = HexToDec(SoSR);
        printf ("Size of stack space that is to be reserved: %u bytes\n", SoSRn);
    }
    else
    {
        unsigned char SoSR[8] = {*(buffer+IOH+79), *(buffer+IOH+78), *(buffer+IOH+77), *(buffer+IOH+76), *(buffer+IOH+75), *(buffer+IOH+74), *(buffer+IOH+73), *(buffer+IOH+72)};
        uint64_t SoSRn = HexToDec64(SoSR);
        printf ("Size of stack space that is to be reserved: %llu bytes\n", SoSRn);
    }

    /* The SizeOfStackCommit field within the PE File Header
     * gives the size of the stack that is to be committed for the image file within the reserved space
     * The rest is made available one page at a time until the reserve size is reached
     */
    if (MNn == 267)
    {
        unsigned char SoSC[4] = {*(buffer+IOH+79), *(buffer+IOH+78), *(buffer+IOH+77), *(buffer+IOH+76)};
        uint32_t SoSCn = HexToDec(SoSC);
        printf ("Size of stack space that is to be committed: %u bytes\n", SoSCn);
    }
    else
    {
        unsigned char SoSC[8] = {*(buffer+IOH+87), *(buffer+IOH+86), *(buffer+IOH+85), *(buffer+IOH+84), *(buffer+IOH+83), *(buffer+IOH+82), *(buffer+IOH+81), *(buffer+IOH+80)};
        uint64_t SoSCn = HexToDec64(SoSC);
        printf ("Size of stack space that is to be committed: %llu bytes\n", SoSCn);
    }

    /* The SizeOfHeapReserve field within the PE File Header
     * gives the memory(in bytes) of the local heap that is to be reserved for the image file
     */
    if (MNn == 267)
    {
        unsigned char SoHR[4] = {*(buffer+IOH+83), *(buffer+IOH+82), *(buffer+IOH+81), *(buffer+IOH+80)};
        uint32_t SoHRn = HexToDec(SoHR);
        printf ("Size of heap space that is to be reserved: %u bytes\n", SoHRn);
    }
    else
    {
        unsigned char SoHR[8] = {*(buffer+IOH+95), *(buffer+IOH+94), *(buffer+IOH+93), *(buffer+IOH+92), *(buffer+IOH+91), *(buffer+IOH+90), *(buffer+IOH+89), *(buffer+IOH+88)};
        uint64_t SoHRn = HexToDec64(SoHR);
        printf ("Size of heap space that is to be reserved: %llu bytes\n", SoHRn);
    }

    /* The SizeOfHeapCommit field within the PE File Header
     * gives the size of the local heap that is to be committed for the image file within the reserved space
     * The rest is made available one page at a time until the reserve size is reached
     */
    if (MNn == 267)
    {
        unsigned char SoHC[4] = {*(buffer+IOH+87), *(buffer+IOH+86), *(buffer+IOH+85), *(buffer+IOH+84)};
        uint32_t SoHCn = HexToDec(SoHC);
        printf ("Size of heap space that is to be committed: %u\n", SoHCn);
    }
    else
    {
        unsigned char SoHC[8] = {*(buffer+IOH+103), *(buffer+IOH+102), *(buffer+IOH+101), *(buffer+IOH+100), *(buffer+IOH+99), *(buffer+IOH+98), *(buffer+IOH+97), *(buffer+IOH+96)};
        uint64_t SoHCn = HexToDec64(SoHC);
        printf ("Size of heap space that is to be committed: %llu bytes\n", SoHCn);
    }

    /* The NumberOfRvaAndSizes field within the PE File Header
     * gives the number of data-directory entries in the remainder of the Image Optional Header
     */
    if (MNn == 267)
    {
        unsigned char NoRaS[4] = {*(buffer+IOH+95), *(buffer+IOH+94), *(buffer+IOH+93), *(buffer+IOH+92)};
        uint32_t NoRaSn = HexToDec(NoRaS);
        printf ("Number of data directory entries: %u\n", NoRaSn);
    }
    else
    {
        unsigned char NoRaS[4] = {*(buffer+IOH+111), *(buffer+IOH+110), *(buffer+IOH+109), *(buffer+IOH+108)};
        uint32_t NoRaSn = HexToDec(NoRaS);
        printf ("Number of data directory entries: %u\n", NoRaSn);
    }
    /* The Windows-specific fields within the Image Optional Header end here
     * The fields that are reserved and always have the value 0 have been left out in the output of the program
     */

    
    /* Data Directory section starts from here
     * It's the last part of the Image Optional Header
     * Each data directory is a 8-byte field that gives the relative virtual address and size(in bytes) of the tables or strings 
     * that are loaded into memory during execution so that the OS can use them at run-time, 
     * both fields being 4-bytes each
     * The relative virtual address is the address of the table relative to the base address of the image(ImageBase)
     * when the table is loaded into memory
     */
    printf ("\nData Directories --\n");
    printf ("If any data directory entry isn't present, its RVA will be shown as 0x0000\n\n");

    /* This program will check for the presence of most of the data directory entries
     * and will output their respective relative virtual addresses and size
     * If the respective data directory entry isn't present,
     * it'll show the offset output for that specific data directory as 0x0000
     */

    // This data directory entry contains the RVA and size of the export table (.edata section) 
    if (MNn == 267)
    {
        printf ("Export Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+99), *(buffer+IOH+98), *(buffer+IOH+97), *(buffer+IOH+96));
        unsigned char et[4] = {*(buffer+IOH+103), *(buffer+IOH+102), *(buffer+IOH+101), *(buffer+IOH+100)};
        uint32_t etn = HexToDec(et);
        printf ("Export Table size: %u bytes\n\n", etn);
    }
    else
    {
        printf ("Export Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+115), *(buffer+IOH+114), *(buffer+IOH+113), *(buffer+IOH+112));
        unsigned char et[4] = {*(buffer+IOH+119), *(buffer+IOH+118), *(buffer+IOH+117), *(buffer+IOH+116)};
        uint32_t etn = HexToDec(et);
        printf ("Export Table size: %u bytes\n\n", etn);
    }

    // This data directory entry contains the RVA and size of the import table (.idata section) 
    if (MNn == 267)
    {
        printf ("Import Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+107), *(buffer+IOH+106), *(buffer+IOH+105), *(buffer+IOH+104));
        unsigned char it[4] = {*(buffer+IOH+111), *(buffer+IOH+110), *(buffer+IOH+109), *(buffer+IOH+108)};
        uint32_t itn = HexToDec(it);
        printf ("Import Table size: %u bytes\n\n", itn);
    }
    else
    {
        printf ("Import Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+123), *(buffer+IOH+122), *(buffer+IOH+121), *(buffer+IOH+120));
        unsigned char it[4] = {*(buffer+IOH+127), *(buffer+IOH+126), *(buffer+IOH+125), *(buffer+IOH+124)};
        uint32_t itn = HexToDec(it);
        printf ("Import Table size: %u bytes\n\n", itn);
    }

    // This data directory entry contains the RVA and size of the resource table (.rsrc section)
    if (MNn == 267)
    {
        printf ("Resource Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+115), *(buffer+IOH+114), *(buffer+IOH+113), *(buffer+IOH+112));
        unsigned char rt[4] = {*(buffer+IOH+119), *(buffer+IOH+118), *(buffer+IOH+117), *(buffer+IOH+116)};
        uint32_t rtn = HexToDec(rt);
        printf ("Resource Table size: %u bytes\n\n", rtn);
    }
    else
    {
        printf ("Resource Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+131), *(buffer+IOH+130), *(buffer+IOH+129), *(buffer+IOH+128));
        unsigned char rt[4] = {*(buffer+IOH+135), *(buffer+IOH+134), *(buffer+IOH+133), *(buffer+IOH+132)};
        uint32_t rtn = HexToDec(rt);
        printf ("Resource Table size: %u bytes\n\n", rtn);   
    }

    // This data directory entry contains the RVA and size of the exception table (.pdata section)
    if (MNn == 267)
    {
        printf ("Exception Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+123), *(buffer+IOH+122), *(buffer+IOH+121), *(buffer+IOH+120));
        unsigned char et[4] = {*(buffer+IOH+127), *(buffer+IOH+126), *(buffer+IOH+125), *(buffer+IOH+124)};
        uint32_t etn = HexToDec(et);
        printf ("Exception Table size: %u bytes\n\n", etn);
    }
    else
    {
        printf ("Exception Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+139), *(buffer+IOH+138), *(buffer+IOH+137), *(buffer+IOH+136));
        unsigned char et[4] = {*(buffer+IOH+143), *(buffer+IOH+142), *(buffer+IOH+141), *(buffer+IOH+140)};
        uint32_t etn = HexToDec(et);
        printf ("Exception Table size: %u bytes\n\n", etn);   
    }

    // This data directory entry contains the RVA and size of the attribute certificate table 
    if (MNn == 267)
    {
        printf ("Attribute Certificate Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+131), *(buffer+IOH+130), *(buffer+IOH+129), *(buffer+IOH+128));
        unsigned char atc[4] = {*(buffer+IOH+135), *(buffer+IOH+134), *(buffer+IOH+133), *(buffer+IOH+132)};
        uint32_t atcn = HexToDec(atc);
        printf ("Attribute Certificate Table size: %u bytes\n\n", atcn);
    }
    else
    {
        printf ("Attribute Certificate Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+147), *(buffer+IOH+146), *(buffer+IOH+145), *(buffer+IOH+144));
        unsigned char atc[4] = {*(buffer+IOH+151), *(buffer+IOH+150), *(buffer+IOH+149), *(buffer+IOH+148)};
        uint32_t atcn = HexToDec(atc);
        printf ("Attribute Certificate Table size: %u bytes\n\n", atcn);   
    }

    // This data directory entry contains the RVA and size of the base relocation table (.reloc section)
    if (MNn == 267)
    {
        printf ("Base Relocation Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+139), *(buffer+IOH+138), *(buffer+IOH+137), *(buffer+IOH+136));
        unsigned char brt[4] = {*(buffer+IOH+143), *(buffer+IOH+142), *(buffer+IOH+141), *(buffer+IOH+140)};
        uint32_t brtn = HexToDec(brt);
        printf ("Base Relocation Table size: %u bytes\n\n", brtn);
    }
    else
    {
        printf ("Base Relocation Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+155), *(buffer+IOH+154), *(buffer+IOH+153), *(buffer+IOH+152));
        unsigned char brt[4] = {*(buffer+IOH+159), *(buffer+IOH+158), *(buffer+IOH+157), *(buffer+IOH+156)};
        uint32_t brtn = HexToDec(brt);
        printf ("Base Relocation Table size: %u bytes\n\n", brtn);
    }

    // This data directory entry contains the RVA and size of the debug data (.debug section)
    if (MNn == 267)
    {
        printf ("Debug Data Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+147), *(buffer+IOH+146), *(buffer+IOH+145), *(buffer+IOH+144));
        unsigned char ddt[4] = {*(buffer+IOH+151), *(buffer+IOH+150), *(buffer+IOH+149), *(buffer+IOH+148)};
        uint32_t ddtn = HexToDec(ddt);
        printf ("Debug Data Table size: %u bytes\n\n", ddtn);
    }
    else
    {
        printf ("Debug Data Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+163), *(buffer+IOH+162), *(buffer+IOH+161), *(buffer+IOH+160));
        unsigned char ddt[4] = {*(buffer+IOH+167), *(buffer+IOH+166), *(buffer+IOH+165), *(buffer+IOH+164)};
        uint32_t ddtn = HexToDec(ddt);
        printf ("Debug Data Table size: %u bytes\n\n", ddtn);
    }

    // This data directory entry contains the RVA and size of the thread local storage table (.tls section)
    if (MNn == 267)
    {
        printf ("Thread Local Storage Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+171), *(buffer+IOH+170), *(buffer+IOH+169), *(buffer+IOH+168));
        unsigned char tlst[4] = {*(buffer+IOH+175), *(buffer+IOH+174), *(buffer+IOH+173), *(buffer+IOH+172)};
        uint32_t tlstn = HexToDec(tlst);
        printf ("Thread Local Storage Table size: %u bytes\n\n", tlstn);
    }
    else
    {
        printf ("Thread Local Storage Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+187), *(buffer+IOH+186), *(buffer+IOH+185), *(buffer+IOH+184));
        unsigned char tlst[4] = {*(buffer+IOH+191), *(buffer+IOH+190), *(buffer+IOH+189), *(buffer+IOH+188)};
        uint32_t tlstn = HexToDec(tlst);
        printf ("Thread Local Storage Table size: %u bytes\n\n",tlstn);
    }

    // This data directory entry contains the RVA and size of the load configuration table
    if (MNn == 267)
    {
        printf ("Load Configuration Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+179), *(buffer+IOH+178), *(buffer+IOH+177), *(buffer+IOH+176));
        unsigned char lct[4] = {*(buffer+IOH+183), *(buffer+IOH+182), *(buffer+IOH+181), *(buffer+IOH+180)};
        uint32_t lctn = HexToDec(lct);
        printf ("Load Configuration Table size: %u bytes\n\n", lctn);
    }
    else
    {
        printf ("Load Configuration Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+195), *(buffer+IOH+194), *(buffer+IOH+193), *(buffer+IOH+192));
        unsigned char lct[4] = {*(buffer+IOH+199), *(buffer+IOH+198), *(buffer+IOH+197), *(buffer+IOH+196)};
        uint32_t lctn = HexToDec(lct);
        printf ("Load Configuration Table size: %u bytes\n\n", lctn);   
    }

    // This data directory entry contains the RVA and size of the bound import table
    if (MNn == 267)
    {
        printf ("Bound Import Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+187), *(buffer+IOH+186), *(buffer+IOH+185), *(buffer+IOH+184));
        unsigned char bit[4] = {*(buffer+IOH+191), *(buffer+IOH+190), *(buffer+IOH+189), *(buffer+IOH+188)};
        uint32_t bitn = HexToDec(bit);
        printf ("Bound Import Table size: %u bytes\n\n", bitn);
    }
    else
    {
        printf ("Bound Import Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+203), *(buffer+IOH+202), *(buffer+IOH+201), *(buffer+IOH+200));
        unsigned char bit[4] = {*(buffer+IOH+207), *(buffer+IOH+206), *(buffer+IOH+205), *(buffer+IOH+204)};
        uint32_t bitn = HexToDec(bit);
        printf ("Bound Import Table size: %u bytes\n\n", bitn);
    }

    // This data directory entry contains the RVA and size of the import address table
    if (MNn == 267)
    {
        printf ("Import Address Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+195), *(buffer+IOH+194), *(buffer+IOH+193), *(buffer+IOH+192));
        unsigned char iat[4] = {*(buffer+IOH+199), *(buffer+IOH+198), *(buffer+IOH+197), *(buffer+IOH+196)};
        uint32_t iatn = HexToDec(iat);
        printf ("Import Address Table size: %u bytes\n\n", iatn);
    }
    else
    {
        printf ("Import Address Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+211), *(buffer+IOH+210), *(buffer+IOH+209), *(buffer+IOH+208));
        unsigned char iat[4] = {*(buffer+IOH+215), *(buffer+IOH+214), *(buffer+IOH+213), *(buffer+IOH+212)};
        uint32_t iatn = HexToDec(iat);
        printf ("Import Address Table size: %u bytes\n\n", iatn);
    }

    // This data directory entry contains the RVA and size of the delay-load import table
    if (MNn == 267)
    {
        printf ("Delay-load Import Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+203), *(buffer+IOH+202), *(buffer+IOH+201), *(buffer+IOH+200));
        unsigned char did[4] = {*(buffer+IOH+207), *(buffer+IOH+206), *(buffer+IOH+205), *(buffer+IOH+204)};
        uint32_t didn = HexToDec(did);
        printf ("Delay-load Import Table size: %u bytes\n\n\n", didn);
    }
    else
    {
        printf ("Delay-load Import Table RVA: 0x%X%X%X%X\n", *(buffer+IOH+219), *(buffer+IOH+218), *(buffer+IOH+217), *(buffer+IOH+216));
        unsigned char did[4] = {*(buffer+IOH+223), *(buffer+IOH+222), *(buffer+IOH+221), *(buffer+IOH+220)};
        uint32_t didn = HexToDec(did);
        printf ("Delay-load Import Table size: %u bytes\n\n\n", didn);
    }

    /* This is the end of the data directory section which ends the Image Optional Header
     * Data directory entries that are reserved for future use always having value 0,
     * or those that are Object-only haven't been added here
     */
}