#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "SDES.h"

void CBCHash(const char* , const char [2], char [3] , char [2]);
int hexCharToInt(char); 
char hexIntToChar(int );

int main(){
    
    char inputBuffer[256];
    char stringBuffer[256];
    char hexOutput[2];
    char key[4] = "000"; //default key
    char IV[3] = "00"; //default IV

    //input string
    printf("Enter input string: ");
    fgets(inputBuffer, sizeof(inputBuffer)-1, stdin);
    inputBuffer[strcspn(inputBuffer, "\r\n")] = '\0'; // Remove newline character
    sscanf(inputBuffer, "%255s", stringBuffer);

    //key 
    printf("Enter key (3 hex digits, default 000): ");
    fgets(inputBuffer, sizeof(inputBuffer)-1, stdin);
    inputBuffer[strcspn(inputBuffer, "\r\n")] = '\0'; // Remove newline character
    sscanf(inputBuffer, "%3s", key);
    if (strlen(key) != 3 || strspn(key, "0123456789abcdefABCDEF") != 3) {
        printf("Invalid key input. Using default key '000'.\n");
        strcpy(key, "000");
    }
    
    //Initialization vector
    printf("Enter IV (2 hex digits, default 00): ");
    fgets(inputBuffer, sizeof(inputBuffer)-1, stdin);
    inputBuffer[strcspn(inputBuffer, "\r\n")] = '\0'; // Remove newline character
    sscanf(inputBuffer, "%2s", IV);
    if( strlen((const char*)IV) != 2 || strspn((const char*)IV, "0123456789abcdefABCDEF") != 2) {
        printf("Invalid IV input. Using default IV '00'.\n");
        strcpy((char*)IV, "00");
    }

    
    printf("Key: %s, IV: %s\n", key, IV);

    CBCHash(stringBuffer, IV, key, hexOutput);

    printf("CBC Hash Output: %s\n", hexOutput);

    return 0;
}


// Input: input buffer to be hashed in plaintext, IV (2 hex characters), key (3 hex characters) 
// Output: output buffer 
void CBCHash(const char* inputBuffer, const char IV[2], char key[3] , char output[2]) {
    const int inputLength = strlen(inputBuffer);

    output[0] = IV[0]; // Initialize output with IV
    output[1] = IV[1];
    
    char currentBlock[3];

    for (int i = 0; i < inputLength; i++) {
        
        // Convert the characters into 2 hex digits
        sprintf(currentBlock, "%02X", (char)inputBuffer[i]);

        //DEBUG PRINT
        // printf("Current Block: %s\n", currentBlock);
        
        // XOR with previous output (or IV for the first block)
        for (int j = 0; j < 2; j++) {
            // Convert hex characters to integer, XOR, then convert back to hex character
            int prevHexValue = hexCharToInt(output[j]);
            int currHexValue = hexCharToInt(currentBlock[j]);
            int xorResult = prevHexValue ^ currHexValue;

            currentBlock[j] = hexIntToChar(xorResult);
        }
        
        SDES(currentBlock, key, output);

        //DEBUG PRINT
        // printf("After SDES Output: %s\n", output);
    }

}

int hexCharToInt(char character) {
    if (character >= '0' && character <= '9') {
        return character - '0';
    } else if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    } else if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    } else {
        return -1; // Invalid hex character
    }
}

char hexIntToChar(int value) {
    if (value >= 0 && value <= 9) {
        return '0' + value;
    } else if (value >= 10 && value <= 15) {
        return 'A' + (value - 10);
    } else {
        return '\0'; // Invalid value
    }
}