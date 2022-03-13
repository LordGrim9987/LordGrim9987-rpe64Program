#include <stdio.h>      // for standard I/O
#include <stdint.h>     //for uint16_t, uint32_t and uint64_t

int FilenameValid (char[]);
int FiletypeValid (const char*);
void FilenameCheck (char[]);
void FiletypeCheck (const char*);
int ExecutableFieldValues2 (const char*);
void ExecutableFieldValues (const char*);
uint32_t HexToDec (unsigned char[]);
uint16_t HexToDec16 (unsigned char[]);
uint64_t HexToDec64 (unsigned char[]);
void help();
void ExecutableSectionInfo (const char*);

#define MAX_ARG 3