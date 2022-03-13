1. Before trying to compile, ensure that a newer version of GCC is installed that supports C17 standard.

2. To compile the source code into the rpe64 program in Unix-based machines, open a terminal in the containing folder of the source code, i.e. the 'rpe64Program' folder
   and run- 'make rpe64'.

2. To compile the source code into the rpe64 program in Windows machines, follow the instruction on line 24 of the Makefile.

4. A help function is present in the 'rpe64Main.c' source file which will be executed when the user uses wrong command-line arguments or gets the order wrong.
   It has info on various functionalities of the program and how to use them.

5. To use the program with the default interface, run- './rpe64 <input image file name>.exe' 
   after compilation within the same directory (if the program hasn't been compiled yet).

6. To get PE File Header info or Section Header info of the input image file directly by skipping the default interface, 
   run- './rpe64 -e <input image file name>.exe', or './rpe64 -s <input image file name>.exe' respectively
   after compilation within the same directory (if the program hasn't been compiled yet).

7. Ensure that the input image file is in the same directory as the rpe6 program, unless you've installed it in the default directory for Linux terminal commands,
   i.e. within/as a subdirectory within the '/bin' directory.