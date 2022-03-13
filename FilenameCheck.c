/* C-program file that contains the
   code for the function to check
   the validity of the executable's filename

   This functionionality of rpe64 only checks if the filename of the executable
   is using some Reserved characters or Reserved names, 
   or if it has a period at the end of the filename,
   as per the Microsoft Doc referenced below.
   It doesn't check for Path validity, Drive letters or Namespaces
 */

/* Written by Ranit Barman as a part of the Academia Internship project under Tezpur University

   Reference material used: https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file
 */

#include <string.h>
#include "rpe64Header.h"

/* The following finction is used to check whether then name of a given executable is valid or not.
 * It takes the name of the executable that is passed to it from the main function as the argument,
 * and passes it to the actual filename-checking function as a string parameter.
 * It returns nothing and simply displays a string in the standard output.
 */
void FilenameCheck(char argf[])
{
    if (!FilenameValid(argf))               /* Passes the name of exe to the filename-checking function as a string parameter,
                                             * and prints a string saying the filename of the given exe is valid if the invoked function returns 0,
                                             * otherwise prints a string saying the filename of the given exe is invalid.
                                             */
        printf("\nThe filename of the given executable is valid\n\n");
    else
        printf("\nThe filename of the given executable is invalid since it's using some reserved names or characters.\n\n");
}

/* This is the actual function that checks if the filename of the executable
 * follows the Microsoft file-naming standards or not.
 * 
 * It takes the name of the exe as a string parameter, and
 * it returns 0 if it does follow the naming standards, otherwise it returns 1.
 */
int FilenameValid(char exeName[])
{
    int i, j;
    
    //Illegal characters for naming executables
    char reservedChars[] = {'<', '>', ':', '"', '\\', '/', '|', '?', '*', '\0'};

    //Reserved names that can't be used for naming executables
    char reservedNames[][4] = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
                               "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"};

    //Lowercase of the reserved names that can't be used for naming executables
    char reservedNamesLo[][4] = {"con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
                                 "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"};

    size_t len = strlen(exeName);

    /* Microsoft recommends not to use a period at the end of the filename of an executable
     * This functionality tests if the executable has a period at the end of its filename,
     * and returns 1 if it does
     */
    if (exeName[len - 5] == '.')
    {
        printf("\nThis executable has a period at the end of its filename.\n");
        return 1;
    }

    else
    {
        for (i = 0; i < len; i++)
        {
            for (j = 0; j < 10; j++)
            {
                if (exeName[i] == reservedChars[j])
                    return 1;       /* returns 1 if any of the reserved characters are used,
                                     * i.e. if the filename is invalid because of using illegal characters in the filename
                                     * 1 is returned
                                     */
            }
        }

        for (j = 0; j < 22; j++)
        {
            if (!((strcmp(reservedNames[j], exeName)) || (strcmp(reservedNamesLo[j], exeName))))
                return 1;               /* returns 1 if any of the reserved names are used,
                                         * i.e. if the filename is invalid because of using Microsoft reserved names,
                                         * 1 is returned
                                         */
        }
    }

    return 0;       /* returns 0 if none of the previous conditions are satisfied,
                     * i.e. if none of the reserved characters and reserved names are used
                     * in the exe filename
                     */
}