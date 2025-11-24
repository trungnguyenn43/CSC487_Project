#include "DiffHellman.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <stdlib.h>
#include <math.h>
#include <ctime>

int DiffHellman_GenPublicKey(int *exp, int* alpha, int *prime)
{   
    if(*prime == 0 && *alpha == 0){
        getRandomPrime(prime, alpha);
    }

    if(*prime == -1 || *alpha == -1){
        return -1; // Error in getting prime and primitive root
    }

    if(*exp == 0){
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
    srand(time(NULL));
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

// FMEA - Fast Modular Exponentiation
// Input: base, exponent, mod
// Output: (base^exponent) % mod
int modExp(int base, int exp, const int mod)
{

    int result = 1; // Initialize result
    base = base % mod; // Ensure base is within mod range

    if (base == 0) return 0; // If base is divisible by mod, result is 0

    while (exp > 0)
    {
        // If the current bit of exp is 1, multiply result with base
        if (exp % 2 == 1)
        {
            result = (result * base) % mod;
        }

        // Square the base and reduce it modulo mod
        base = (base * base) % mod;

        // Right shift exp by 1 bit (equivalent to dividing by 2)
        exp = exp / 2;
    }

    // Ensure result is non-negative
    if (result < 0)
    {
        result += mod;
    }

    return result;
}
