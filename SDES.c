#include "SDES.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

//* Global Variables *//
#pragma region global variables
extern char plaintext[9] = ""; // 8-bit binary string + null terminator \0
extern char keytext[13] = "";       // 12-bit key + null terminator. The first 2 bits are ignored
char KEY1[9] = "";       // First 8-bit subkey + null terminator
char KEY2[9] = "";       // Second 8-bit subkey + null terminator
#pragma endregion


//* Entry Point of the SDES algorithm *//
char* SDES(char* plaintextInput, char* keyInput) {
    
    // ? Validate inputs
    if(plaintextInput == NULL || keyInput == NULL) {
        fprintf(stderr, "Error: Empty input (code: 1)\n");
        return NULL;
    }

    if(keyInput[0] != '0' && keyInput[0] != '1' && keyInput[0] != '2' && keyInput[0] != '3'){ // Fixed logical condition
        fprintf(stderr, "Error: Invalid plaintext input (code: 2)\n");
        return NULL;
    }

        
    {   // Initial step: Convert the plaintext and key from hex to binary
        strcpy(plaintext, hex2Bin(plaintextInput));
        strcpy(keytext, hex2Bin(keyInput));

        
        //*Ignore the first 2 bits of the key
        // shift left by 2 to move the first 2 bits to last 2 positions
        strcpy(keytext, ls_block(keytext, 2));
        keytext[strlen(keytext)-1] = '\0'; // Null terminate after ignoring first 2 bits
        keytext[strlen(keytext)-1] = '\0';

        //little note: strlen -> count the character in the string until it reach null terminator \0
        //hence, -1 to get the last character always
    }

    
    return plaintext;
}

//* Convert Hexadecimal to Binary *//
char* hex2Bin(const char* hex) {

    char* output = (char*) malloc( (strlen(hex) * 4 + 1) * sizeof(char) ); // 4 bits per hex digit + null terminator

    if(output == NULL) {
        fprintf(stderr, "Error: Memory allocation failed (code: 3)\n");
        return NULL;
    }

    // Convert each hex digit to its 4-bit binary equivalent
    for (int i = 0; i < strlen(hex); i++) {
        char* bin = hexDigitsToBin(hex[i]);
        if (bin == NULL || *bin == '\0') {
            // Clear the output in case of error
            memset(output, 0, strlen(output));
            return NULL;
        }
        strcat(output, bin);
    }

    return output;
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

char* ls_block(char* input, int shiftCount) {
    
    int size = strlen(input); // Get the input string length

    for(int i = 0; i < shiftCount; i++) {
        // Store the first bit
        char first_bit = input[0];
        
        // Shift all bits to the left
        for (int j = 0; j < size; j++) {
            input[j] = input[j + 1];
        }

        // Place the first bit at the end
        input[size - 1] = first_bit;

    }
    
    return input;
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

