
#include "DiffHellman.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <stdlib.h>
#include <math.h>
#include <time.h>

int DiffHellman_GenPublicKey(int *exp, int *prime)
{

    srand(time(0));

    *prime = getRandomPrime();
    if (*prime == -1)
    {
        return -1; // Exit if there was an error getting a prime
    }

    // Random integer in the range [1, prime-1]
    *exp = rand() % (*prime - 2) + 1;

    int alpha = primitiveRoot(*prime);
    printf("INFO: Using alpha: %d\n", alpha);

    int publicKey = modExp(alpha, *exp, *prime);

    return publicKey;
}

int DiffHellman_GenShareKey(const int alpha, const int exp, const int prime)
{
    return modExp(alpha, exp, prime);
}

int getRandomPrime()
{
    FILE *file;
    file = fopen("primes.txt", "r");

    if (file == NULL)
    {
        printf("Could not open file primes.txt\n");
        fclose(file);
        return -1; // Return an error code
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
    }

    fclose(file);
    return atoi(line); // Convert the selected line to an integer and return it
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

int primitiveRoot(int prime)
{
    // Loop through potential primitive roots starting from 2
    for (int r = 2; r <= prime; r++)
    {
        bool flag = true; // Assume r is a primitive root
        // Check if r^i mod prime == 1 for any i in [1, prime-1)
        // If it does, then r is not a primitive root
        for (int i = 1; i < prime - 1; i++)
        {
            if (gcd(r, prime) != 1 && modExp(r, i, prime) == 1)
            {
                flag = false; // r is not a primitive root -> break
                break;
            }
        }
        // If r is a primitive root, return it
        if (flag)
        {
            return r;
        }
    }
    return -1; // No primitive root found
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