#include "rpe64Header.h"

/* Programs to convert a hexadecimal number taken as string input 
 * into a decimal number
 */
uint32_t HexToDec (unsigned char hex[])
{   
    uint32_t hexn;
    
    hexn = (uint32_t)hex[0] << 24 |
           (uint32_t)hex[1] << 16 |
           (uint32_t)hex[2] << 8  |
           (uint32_t)hex[3];
           
    return hexn;
}

uint16_t HexToDec16 (unsigned char hex[])
{   
    uint16_t hexn;
    
    hexn = (uint16_t)hex[0] << 8 |
           (uint16_t)hex[1]; 
    
    return hexn;
}

uint64_t HexToDec64 (unsigned char hex[])
{   
    uint32_t hexn;
    
    hexn = (uint64_t)hex[0] << 56 |
           (uint64_t)hex[1] << 48 |
           (uint64_t)hex[2] << 40 |
           (uint64_t)hex[3] << 32 |
           (uint64_t)hex[4] << 24 |
           (uint64_t)hex[5] << 16 |
           (uint64_t)hex[6] << 8  |
           (uint64_t)hex[7];
           
    return hexn;
}