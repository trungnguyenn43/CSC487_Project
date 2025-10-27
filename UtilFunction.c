
#include <stdio.h>
#include <stdlib.h>
#include <ctime>
#include <string.h>

#include "UtilFunction.h"
#include "SDES.h"

// =============================================================
// Project 2D: RSA Key Generation
// =============================================================
// Input: two prime numbers p and q, eOut (if = 0, create new e)
// output: d - multiplicative inverse of e mod totient, where totient = (p-1)*(q-1)
unsigned int RSA_KeyGen(unsigned int p, unsigned int q, unsigned int* eOut){

    
    if(*eOut == 0){
        printf("eOut is not provided. Selecting a new e\n");
        *eOut = selectE_RSA((q-1) * (p-1));
        printf("Chosen e: %u\n", *eOut);
    }

    return multiplicativeInverse((p - 1) * (q - 1), *eOut);
    
}

unsigned int selectE_RSA(unsigned int totient){

    srand(time(NULL));

    unsigned int e = 2;
    unsigned int eList[25]; //possible e values
    int eCount = 0; // count of eList elements

    // Find e such that gcd(e, totient) = 1
    while(e < totient && eCount < 25){
        if(gcd(e, totient) == 1){
            eList[eCount] = e;
            eCount++;
        }
        e++;
    }

    // Randomly select e from the list
    int randomIndex = rand() % eCount;
    e = eList[randomIndex];

    return e;
}

// =============================================================
// Project 2C: Totient Multiplicative Inverse Calculation
// =============================================================
// Input: two prime numbers p and q, eOut (if = 0, create new e)
// output: multiplicative inverse of e mod totient, where totient = (p-1)*(q-1)
unsigned int totientMultiplcativeInverse(unsigned int p, unsigned int q, unsigned int* eOut){

    if(*eOut == 0){
        printf("eOut is not provided. Selecting a new e\n");
        *eOut = selectE_2Primes(q, p);
        printf("Chosen e: %u\n", *eOut);
    }
    
    return multiplicativeInverse((p - 1) * (q - 1), *eOut);
    
}


unsigned int selectE_2Primes(unsigned int q, unsigned int p){

    srand(time(NULL));

    unsigned int e = 2;
    unsigned int eList[25]; //possible e values
    int eCount = 0; // count of eList elements

    // Find e such that gcd(e, p) = 1 and gcd(e, q) = 1
    while(e < p*q && eCount < 25){
        if(gcd(e, p) == 1 && gcd(e, q) == 1){
            eList[eCount] = e;
            eCount++;
        }
        e++;
    }

    // Randomly select e from the list
    int randomIndex = rand() % eCount;
    e = eList[randomIndex];

    return e;
}

unsigned int multiplicativeInverse(unsigned int totient, unsigned int x){

    int x1, y1; // To store results of extendedEuclidean

    // if gcd(x, totient) != 1, multiplicative inverse doesn't exist
    unsigned int gcd = extendedEuclidean(x, totient, &x1, &y1);

    if(gcd != 1){
        return 0; // Indicate that inverse doesn't exist
    }

    //if x1 is negative, make it positive
    if(x1 < 0){
        x1 = totient + x1;
    }
    
    return x1;
}

unsigned int extendedEuclidean(unsigned int remainder, unsigned int quotient, int* x, int* y){

    /* NOTE
        ax + by = d = gcd(a,b)
        where a = quotient, b = remainder
        => d = quotient*x + remainder*y

        Multiplicative inverse of a mod b is x when d = 1
    */

    // Stop condition
    if(remainder == 0){
        // y = 1, x = 0 at last step when remainder is 0
        *x = 0;
        *y = 1;
        return quotient;
    }

    int x1, y1; // To store results of recursive call
    
    // remainder will be quotient in next call
    int d = extendedEuclidean(quotient % remainder, remainder, &x1, &y1);

    /*  Update x and y
        d = quotient*x1 + remainder*y1
        
        result from previous call returns will be the new value for current x and y
        => y = x1
        => x = y1 - (quotient/remainder)*x1
    */
    *x = y1 - (quotient / remainder) * x1;
    *y = x1;

    return d;
}

unsigned int gcd(unsigned int a, unsigned int b)
{
    while (b != 0)
    {
        unsigned int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// =============================================================
// Project 2B: CBC Hash Function Implementation
// =============================================================
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