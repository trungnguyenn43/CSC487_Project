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
    // Validate inputs
    if (plaintextInput == NULL || keyInput == NULL) {
        fprintf(stderr, "Error: Empty input (code: 1)\n");
        return NULL;
    }

    // Check if the first character of the keyInput is valid
    if (keyInput[0] != '0' && keyInput[0] != '1' && keyInput[0] != '2' && keyInput[0] != '3') {
        fprintf(stderr, "Error: Invalid plaintext input (code: 2)\n");
        return NULL;
    }

    {   // Convert plaintext and key from hex to binary
        strcpy(plaintext, hex2Bin(plaintextInput)); // Convert plaintext
        strcpy(keytext, hex2Bin(keyInput));         // Convert key

        // Ignore the first 2 bits of the key by left-shifting twice
        strcpy(keytext, ls_block(keytext, 2));
        keytext[strlen(keytext) - 1] = '\0'; // Null terminate after ignoring first 2 bits
        keytext[strlen(keytext) - 1] = '\0'; // Ensure null termination
    }

    // Generate the two subkeys K1 and K2
    keyGen(keytext);

    return plaintext;
}

//* Convert Hexadecimal to Binary *//
char* hex2Bin(const char* hex) {
    static char output[65]; // Maximum 16 hex digits * 4 bits + null terminator
    memset(output, 0, sizeof(output)); // Clear the output array

    // Convert each hex digit to its 4-bit binary equivalent
    for (int i = 0; i < strlen(hex); i++) {
        const char* bin = hexDigitsToBin(hex[i]);
        if (bin == NULL || *bin == '\0') {
            fprintf(stderr, "Error: Invalid hex digit '%c' (code: 2)\n", hex[i]);
            output[0] = '\0'; // Clear output on error
            return output;
        }
        strcat(output, bin); // Append binary representation
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

//entry point for key generator
void keyGen(char* key) {
    // Generate the two subkeys K1 and K2 from the original 10-bit key
    char* p10_output = p10_block(key); // Apply P10 permutation

    printf("P10 Output: %s\n", p10_output);

    // Split the permuted key into two halves
    char left[6], right[6]; // 5 bits each + null terminator
    strncpy(left, p10_output, 5);
    left[5] = '\0'; // Null terminate
    strncpy(right, p10_output + 5, 5);
    right[5] = '\0'; // Null terminate

    // Perform left shifts
    char* ls1_left = ls_block(left, 1);
    char* ls1_right = ls_block(right, 1);
    printf("LS1 Left: %s, LS1 Right: %s\n", ls1_left, ls1_right);

    //P8 permutation to get KEY1
    strcpy(KEY1, p8_block(ls1_left, ls1_right));
    printf("KEY1: %s\n", KEY1);

    // Perform second left shifts
    char* ls2_left = ls_block(ls1_left, 2);
    char* ls2_right = ls_block(ls1_right, 2);
    printf("LS2 Left: %s, LS2 Right: %s\n", ls2_left, ls2_right);

    //P8 permutation to get KEY2
    strcpy(KEY2, p8_block(ls2_left, ls2_right));
    printf("KEY2: %s\n", KEY2);

    
}

//* Apply P10 Permutation *//
char* p10_block(char* input) {
    static char output[11]; // 10 bits + null terminator
    memset(output, 0, sizeof(output)); // Clear the output array

    // Apply the P10 permutation
    output[0] = input[2];
    output[1] = input[4];
    output[2] = input[1];
    output[3] = input[6];
    output[4] = input[3];
    output[5] = input[9];
    output[6] = input[0];
    output[7] = input[8];
    output[8] = input[7];
    output[9] = input[6];
    output[10] = '\0'; // Null terminator

    return output;
}

//* Left Shift Block with Shift Count *//
char* ls_block(char* input, int shiftCount) {
    int size = strlen(input); // Get the input string length

    for (int i = 0; i < shiftCount; i++) {
        char first_bit = input[0]; // Store the first bit

        // Shift all bits to the left
        for (int j = 0; j < size - 1; j++) {
            input[j] = input[j + 1];
        }

        input[size - 1] = first_bit; // Place the first bit at the end
    }

    return input;
}

char* p8_block(char* left, char* right) {
    static char output[9]; // 8 bits + null terminator
    memset(output, 0, sizeof(output)); // Clear the output array

    char input[17]; // 16 bits from left and right + null terminator
    strcpy(input, left);
    strcat(input, right);

    output[0] = input[5]; 
    output[1] = input[2]; 
    output[2] = input[6]; 
    output[3] = input[3]; 
    output[4] = input[7]; 
    output[5] = input[4]; 
    output[6] = input[9]; 
    output[7] = input[8]; 

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
