#include "SDES.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

//* Global Variables *//
#pragma region global variables
extern char plaintext[9] = ""; // 8-bit binary string + null terminator \a
extern char key[11] = "";       // 10-bit key + null terminator
char KEY1[9] = "";       // First 8-bit subkey + null terminator
char KEY2[9] = "";       // Second 8-bit subkey + null terminator
#pragma endregion


//* Entry Point of the SDES algorithm *//
char* SDES(char* plaintextInput, char* keyInput) {
    
    if(plaintextInput == NULL || keyInput == NULL) {
        fprintf(stderr, "Error: Empty input (code: 1)\n");
        return NULL;
    }

    if(keyInput[0] != '0' && keyInput[0] != '1'){ // Fixed logical condition
        fprintf(stderr, "Error: Invalid plaintext input (code: 2)\n");
        return NULL;
    }

    // Convert the plaintext and key from hex to binary
    hex2Bin(plaintextInput);
    hex2Bin(keyInput);

    return plaintext;
}

//* Convert Hexadecimal to Binary *//
void hex2Bin(const char* hex) {
    // Convert each hex digit to its 4-bit binary equivalent
    for (int i = 0; i < strlen(hex); i++) {
        char* bin = hexDigitsToBin(hex[i]);
        if (bin == NULL) {
            // Clear the plaintext in case of error
            memset(plaintext, 0, sizeof(plaintext));
            return;
        }
        strcat(plaintext, bin);
    }
}

char* hexDigitsToBin(const char hex) {
    // Return a static binary string for each hex digit
    switch (toupper(hex)) {
        case '0': return "0000";
        case '1': return "0001";
        case '2': return "0010";
        case '3': return "0011";
        case '4': return "0100";
        case '5': return "0101";
        case '6': return "0110";
        case '7': return "0111";
        case '8': return "1000";
        case '9': return "1001";
        case 'A': return "1010";
        case 'B': return "1011";
        case 'C': return "1100";
        case 'D': return "1101";
        case 'E': return "1110";
        case 'F': return "1111";
        default: 
            fprintf(stderr, "Error: Invalid hex digit '%c' (code: 2)\n", hex);
            return NULL;
    }
}

void keyGen(char* key) {
    // Generate the two subkeys K1 and K2 from the original 10-bit key
}

char* p10_block(char* input) {
    char* output;
    return output;
}

char* ls_block(char* input, int shifts) {
    char* output;
    for (int i = 0; i < shifts; i++) {
        char first_bit = input[0];
        for (int j = 0; j < 4; j++) {
            input[j] = input[j + 1];
        }
        input[4] = first_bit;
    }
    return output;
}

char* p8_block(char* left, char* right) {
    char* output;
    return output;
}

char* ip_block(char* input) {
    char* output;
    return output;
}

char* ip1_block(char* input) {
    char* output;
    return output;
}

char* ep_block(char* input) {
    char* output;
    return output;
}

char* s1_block(char* input) {
    char* output;
    return output;
}

char* s2_block(char* input) {
    char* output;
    return output;
}

char* p4_block(char* input) {
    char* output;
    return output;
}

