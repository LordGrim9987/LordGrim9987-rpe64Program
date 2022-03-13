/* C-program file that contains the
   code for the function to check
   the validity of the executable.

   This functionionality of rpe64 checks the validity of the filetype
   of the given executable by checking for the presence of the Dword signature
   within the PE File Header as-well-as for the presence of the magic number in the Optional Image Header
   which are only present in PE32 and PE32+ executable files.
   If it's a valid executable, the functionality determines what type of executable
   the given executable file is, i.e. whether it's a x86-64(64-bit) 
   or x86(32-bit) executable, by determining the value of the magic number.
 */

/* Written by Ranit Barman as a part of the Academia Internship project under Tezpur University

   Reference material used: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
 */

#include <stdlib.h>
#include <string.h>
#include "rpe64Header.h"

/* The following function is used to check whether a given executable is valid or not.
 * It takes the executable passed to it by the main function as a character pointer,
 * and then passes it to the actual filetype validity-checking function as a character pointer too.
 * It returns nothing and simply displays strings in the standard output.
 */
void FiletypeCheck(const char *argt)
{
    if (FiletypeValid(argt))     /* Passes the address of exe to the filetype validity-checking function as a character pointer parameter,
                                  * and prints a string saying the filetype of the given exe is valid if the invoked function returns 0,
                                  * otherwise prints a string saying the filetype of the given exe is invalid.
                                  */
      printf("\nThe given executable isn't a valid PE executable and may have been just been named as an 'exe'.\n\n");
}

/* This is the actual function that checks whether the given executable is a valid executable or not,
 * and displays whether it's a 64-bit PE32+ or 32-bit PE32 executable file.
 * 
 * It takes the input executable as a character pointer parameter, and
 * it returns 0 if it is a valid PE executable, otherwise it returns 1.
 * It also prints a string saying whether it's a 64-bit or 32-bit executable by checking
 * the value of its magic number in the Optional Image Header.
 */
int FiletypeValid(const char *exev)
{
  int flag = 0;
    char buffer[512]; // 512 bytes is just a random value that is large enough to hold the required to no. of bytes

    FILE *infile = fopen(exev, "rb");
    // Reads 176 bytes of binary data from the start of the given executable file.
    fread(&buffer, 16, 32, infile);
    fclose(infile);

    unsigned char e_lfanewc[4] = {*(buffer+63), *(buffer+62), *(buffer+61), *(buffer+60)};
    uint32_t e_lfanew = HexToDec(e_lfanewc);    // Stores the PE File Header offset in decimal format
    
    if (strstr(buffer + e_lfanew, "PE")) /* Checks for the presence of the PE file signature(PE\0\0) using string comparison function
                                          * in the given PE File offset and prints a string saying the given execuable is valid
                                          * if the comparison returns true.
                                          */
    {
        printf("\nThe given executable is a valid PE image file since it has the 4-byte Dword signature within the PE File Header.\n");
        flag = 1;
    }
    else
        // If the comparison returns false, it prints a string saying that the given executable is invalid.
        printf("\nThe given executable is NOT a valid PE image file since it doesn't have the 4-byte Dword signature within the PE File Header.\n");

    uint32_t IOH = e_lfanew+24;      // Stores the offset of the Image Optional Header in decimal format
    
    // The following code is executed only if it is found that the given executable is valid.
    if (flag)
    {
        if ((*(buffer + IOH) == 0x0B) && (*(buffer + IOH + 1) == 0x02)) /* Checks what magic code is present in the Image Optional Header, which
                                                                     * is the last part of the PE File Header, and gives the output
                                                                     * accordingly, i.e. gives the output as 64-bit if the magic code present
                                                                     * in the offset 0x00000099 is 0x20b(0B 02), or as 32-bit if the
                                                                     * magic code present is 0x10b(0B 01) in the same offset.
                                                                     */
        {
            printf("\nThe given executable is a 64-bit executable.\n\n");
            return 0;
        }
        else if ((*(buffer + IOH) == 0x0B) && (*(buffer + IOH + 1) == 0x01))
        {
            printf("\nThe given executable is a 32-bit executable.\n\n");
            return 0;
        }
    }

    return 1;
}
