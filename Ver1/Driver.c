#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <unistd.h>

#include "SDES.h"

int getSelection();
char *encryption(char *, char *);
char *decryption(char *, char *);

int main()
{
    bool isExit = false;

    FILE *inputFile;
    FILE *outputFile;

    while (!isExit)
    {
        char line[50];
        char key[4];

        switch (getSelection())
        {
        case 1:
            // Encrypt
            inputFile = fopen("plaintext.txt", "r");
            outputFile = fopen("ciphertext.txt", "w");
            if (inputFile == NULL || outputFile == NULL)
            {
                fprintf(stderr, "Error: Could not open either file\n");
                break;
            }

            printf("Enter 3-digit hexadecimal key>> ");
            scanf("%3s", key);
            // Validate key length
            if (strlen(key) != 3 || !isxdigit(key[0]) || !isxdigit(key[1]) || !isxdigit(key[2]))
            {
                printf("Invalid key. Please enter a 3-digit hexadecimal key.\n");
                fclose(inputFile);
                fclose(outputFile);
                break;
            }

            while (fgets(line, sizeof(line), inputFile))
            {
                // Get only the first 2 characters (2 hex digits)
                strncpy(line, line, 2);
                line[2] = '\0'; // Null terminate

                memset(line + 2, 0, sizeof(line) - 2); // Clear the rest of the line buffer

                // Validate that the line contains exactly 2 hex digits
                if (strlen(line) != 2 || !isxdigit(line[0]) || !isxdigit(line[1]))
                {
                    printf("Invalid plaintext line: %s. Skipping...\n", line);
                    continue; // Skip invalid lines
                }

                char *encrypted = encryption(line, key);
                if (encrypted != NULL)
                {
                    printf("Decrypted line: %s\n", encrypted);
                    fprintf(outputFile, "%.2s\n", encrypted);
                }
                else
                {
                    fprintf(stderr, "Encryption failed for line: %s\n", line);
                }
            }

            fclose(inputFile);
            fclose(outputFile);
            break;

        case 2:
            // Decrypt
            inputFile = fopen("ciphertext.txt", "r");
            outputFile = fopen("plaintext.txt", "w");
            if (inputFile == NULL || outputFile == NULL)
            {
                fprintf(stderr, "Error: Could not open either file\n");
                break;
            }

            printf("Enter 3-digit hexadecimal key>> ");
            scanf("%3s", key);
            // Validate key length
            if (strlen(key) != 3 || !isxdigit(key[0]) || !isxdigit(key[1]) || !isxdigit(key[2]))
            {
                printf("Invalid key. Please enter a 3-digit hexadecimal key.\n");
                fclose(inputFile);
                fclose(outputFile);
                break;
            }

            while (fgets(line, sizeof(line), inputFile))
            {
                // Get only the first 2 characters (2 hex digits)
                strncpy(line, line, 2);
                line[2] = '\0'; // Null terminate

                memset(line + 2, 0, sizeof(line) - 2); // Clear the rest of the line buffer

                // Validate that the line contains exactly 2 hex digits
                if (strlen(line) != 2 || !isxdigit(line[0]) || !isxdigit(line[1]))
                {
                    printf("Invalid plaintext line: %s. Skipping...\n", line);
                    continue; // Skip invalid lines
                }

                char *decrypted = decryption(line, key);
                if (decrypted != NULL)
                {   
                    printf("Decrypted line: %s\n", decrypted);
                    fprintf(outputFile, "%.2s\n", decrypted);
                }
                else
                {
                    fprintf(stderr, "Decryption failed for line: %s\n", line);
                }
            }

            fclose(inputFile);
            fclose(outputFile);
            break;

        case 3:
            // Quit
            isExit = true;
            printf("Exiting the program.\n");
            break;

        default:
            printf("Invalid selection. Please try again.\n");
            break;
        }
    }

    return 0;
}

int getSelection()
{
    int selection;
    char input[10];
    do
    {
        printf("\nSelect an option:\n");
        printf("1. Encrypt\n");
        printf("2. Decrypt\n");
        printf("3. Quit\n");
        printf("Enter your choice >> ");
        scanf("%9s", input);

        // Check if the input is a valid number
        if (strlen(input) == 1 && isdigit(input[0]))
        {
            selection = input[0] - '0';
        }
        else
        {
            selection = 0; // Invalid selection
        }
    } while (selection < 1 || selection > 3);
    return selection;
}

char *encryption(char *plaintextInput, char *keyInput)
{
    return SDES(plaintextInput, keyInput);
}

char *decryption(char *cipherTextInput, char *keyInput)
{
    return SDES_decrypt(cipherTextInput, keyInput);
}
