#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "UtilFunction.h"

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
