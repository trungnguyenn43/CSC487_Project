
#include "DiffHellman.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <stdlib.h>
#include <math.h>
#include <time.h>

int DiffHellman_GenPublicKey(int *exp, int* alpha, int *prime)
{   
    if(*prime == 0 && *alpha == 0){
        getRandomPrime(prime, alpha);
    }

    if(*prime == -1 || *alpha == -1){
        return -1; // Error in getting prime and primitive root
    }

    if(*exp == -1){
        // Random integer in the range [1, prime-1]
        *exp = rand() % (*prime - 2) + 1;
    }

    int publicKey = modExp(*alpha, *exp, *prime);

    return publicKey;
}

int DiffHellman_GenShareKey(const int alpha, const int exp, const int prime)
{
    return modExp(alpha, exp, prime);
}

// getting the random prime and primitive root
void getRandomPrime(int *prime, int *primitiveRoot)
{   
    FILE *file;
    file = fopen("primes.txt", "r");

    if (file == NULL)
    {
        printf("Could not open file primes.txt\n");
        fclose(file);
        *prime = -1;
        *primitiveRoot = -1;
        return; // Return an error code
    }

    // Count the number of lines in the file
    int lineCount = 0;
    char ch;
    while (!feof(file))
    {
        ch = fgetc(file);
        if (ch == '\n')
        {
            lineCount++;
        }
    }

    // Generate a random line number
    int randomLine = rand() % lineCount;
    rewind(file); // Reset file pointer to the beginning
    char line[100];
    for (int i = 0; i <= randomLine; i++)
    {
        fgets(line, sizeof(line), file);
        sscanf(line, "%d %d", prime, primitiveRoot);
    }

    fclose(file);
    return;
}

int modExp(int base, int exp, const int mod)
{

    // c - current expo
    // f - final result
    // a - base
    // m - mod

    int result = 1; // Initialize result
    int currentExpo = 0;

    // convert base to binary
    int binaryExp[32]; // assuming exp is a 32-bit integer
    int index = 0;
    while (exp > 0)
    {
        binaryExp[index++] = exp % 2;
        exp = exp / 2;
    }

    // Perform modular exponentiation using the binary representation
    for (int i = index - 1; i >= 0; i--)
    {
        currentExpo = 2 * currentExpo;
        result = (result * result) % mod; // Square the result
        if (binaryExp[i] == 1)
        {
            currentExpo = currentExpo + 1;
            result = (result * base) % mod; // Multiply by base if the bit is 1
        }
    }

    return result;
}


int gcd(int a, int b)
{
    while (b != 0)
    {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}