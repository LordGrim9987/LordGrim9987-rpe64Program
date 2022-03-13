/* C-program file that contains the
   main function of the rpe64 program
   that calls the the other program files and forms the executable
 */

/* Written by Ranit Barman as a part of the Academia Internship project under Tezpur University

   Reference material used: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
 */

#include <stdlib.h>
#include <unistd.h>     //POSIX header file for getopt() function that helps in command-line arguments
#include "rpe64Header.h"

int main (int argc, char *argv[])
{   
    if (argc == 1)
    {
        help();
        return 1;
    }
    else if (argc > 2)
    {
        char ch;

        while ((ch = getopt(argc, argv, "es")) != EOF)      //POSIX function for command-line arguments
            switch (ch)
            {
                case 'e':
                    ExecutableFieldValues (argv[2]);
                    break;
                case 's':
                    ExecutableSectionInfo (argv[2]);
                    break;
                default: 
                    help();
                    return 1;
            }
            argc -= optind;
            argv += optind;
    }
    else if (argc == 2)
    {
        char choice;

        FilenameCheck(argv[1]);
        FiletypeCheck(argv[1]);

        printf ("\nDo you need additonal information?\n"
                "\nDo you want\n"
                "(A) PE File Header information? (Press 'A')\n"
                "(B) Section Table information? (Press 'B')\n"
                "(C) both (Press 'C')\n"
                "(D) to exit? (Press anything else)\n");
        scanf ("%c", &choice);

        switch (choice)
        {
            case 'c':
            case 'C':            
                ExecutableFieldValues(argv[1]);
            case 'b':
            case 'B': 
                ExecutableSectionInfo(argv[1]);
                break;
            case 'a':
            case 'A':
                ExecutableFieldValues(argv[1]);
                break;
            default:
                printf ("You entered an invalid value, exiting...\n");
                help();
                return 1;
        }
    }

    return 0;
}

void help()
{
    printf ("\n1. The rpe64 program takes one input argument and has two options\n"
            "2. If multiple input files are provided, the program will show nothing\n"
            "3. Always provide the input file as the last command-line argument\n"
            "4. Use the 'e' option for directly accessing PE File Header information\n"
            "5. Use the 's' option for directly accessing Section Header Table information\n"
            "6. If no option is provided, it'll run the default interface of the program\n"
            "7. Only one option can be used at a time, and multiple options can't be combined\n"
            "8. If a valid file isn't provided in the input and some random string is given as input, it'll be shown as Segmentation Fault\n"
            "9. If you use multiple options at the same time or get the order of the command-line arguments wrong, it'll either show Segmentation Fault or do nothing\n"
	        "10. If you forget to provide the '-' prefix before the option you intended to use, the program will do nothing\n\n");
}
