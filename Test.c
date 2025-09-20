#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "SDES.h"

int main(){
    char plaintext[3];
    char key[3];

    printf("Enter 2-digit hexadecimal plaintext: ");
    scanf("%2s", plaintext);

    printf("Enter 3-digit hexadecimal key: ");
    scanf("%3s", key);

    static char output[9]; // 8 bits + null terminator
    strcpy(output, SDES(plaintext, key));

    if (output != NULL) {
        printf("Ciphertext (8-bit binary): %s\n", output);
    } else {
        fprintf(stderr, "Encryption failed due to input error.\n");
    }
    

    return 0;
}