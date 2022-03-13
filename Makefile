FilenameCheck.o: FilenameCheck.c rpe64Header.h
	gcc -std=c17 -Wall -c FilenameCheck.c

FiletypeCheck.o: FiletypeCheck.c rpe64Header.h
	gcc -std=c17 -Wall -c FiletypeCheck.c

HexToDec.o: HexToDec.c rpe64Header.h
	gcc -std=c17 -Wall -c HexToDec.c

ExecutableFieldValues.o: ExecutableFieldValues.c rpe64Header.h
	gcc -std=c17 -Wall -c ExecutableFieldValues.c

ExecutableSectionInfo.o: ExecutableSectionInfo.c rpe64Header.h
	gcc -std=c17 -Wall -c ExecutableSectionInfo.c

rpe64Main.o: rpe64Main.c rpe64Header.h
	gcc -std=c17 -Wall -c rpe64Main.c

rpe64: FilenameCheck.o FiletypeCheck.o HexToDec.o ExecutableFieldValues.o ExecutableSectionInfo.o rpe64Main.o
	gcc *.o -o rpe64


# This Makefile is intended to be run on Unix-based machines
# To compile this in Windows, run- 'gcc FilenameCheck.c FiletypeCheck.c ExecutableFieldValues.c ExecutableSectionInfo.c HexToDec.c rpe64Main.c -std=c17 -Wall -o rpe64' on the command-line on the 'rpe64Program' directory
# This is because Makefile mayn't be available by default on Windows machines