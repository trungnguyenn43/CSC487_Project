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

    char* output = SDES(plaintext, key);

    return 0;
}