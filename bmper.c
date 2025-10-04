/***********************************************************************************************************
*** NAME : Draix Wyatt and Rachel Janssen                                                                ***
*** CLASS : CSc 487                                                                                      ***
*** Project : 1                                                                                          ***
*** DUE DATE : 09-22-25                                                                                  ***
*** INSTRUCTOR : Fourney                                                                                 ***
************************************************************************************************************
*** DESCRIPTION : This driver program implements the SDES module, providing a demonstartion of all       ***
***               functionality. It reads command line arguments, reads the data and feeds it to SDES.   ***
***               Additionally this program has the ability to  to encrypt and decrypt BMP files which   ***
***               is partial fulfillment of the Honors Contract.                                         ***
***********************************************************************************************************/

// Libraries and pre-processor directives
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "SDES.h"

enum OP_MODE {ECB, CBC, CTR};
enum OP_MODE op_mode = ECB; // default mode

// Function headers and global definitions
void ReadInputArgs(char[101], bool *, char[101], bool[10], bool *, bool *, bool *);

// Function main definition
int main(int argc, char *argv[])
{
    char inFileStr[101] = {""};
    bool isE; // isEncrypt - false = D; true = E
    char outFileStr[101] = {""};
    bool key[10] = {false};
    bool exit = false;
    bool error = false;
    bool isKey = false;
    FILE *inFile;
    FILE *outFile;
    char headerBuffer[54] = {""}; // Not used as a c-string; no \0
    unsigned char inputByte = 0;
    bool inputBits[8] = {false};
    bool outputBits[8] = {false};
    unsigned char outputByte = 0;
    size_t bytesR_W;

    // Main body loop; supports multiple commands per program run
    while (!exit)
    {
        memset(inFileStr, 0, sizeof(inFileStr));
        memset(outFileStr, 0, sizeof(outFileStr));
        memset(key, 0, sizeof(key));
        isKey = false;
        memset(headerBuffer, 0, sizeof(headerBuffer));

        do
        {
            // Reset error flag and print message if necessary
            if (error)
            {
                error = false;
                printf("ERROR: Invalid input detected!\n\n");
            }

            ReadInputArgs(inFileStr, &isE, outFileStr, key, &isKey, &error, &exit);
            printf("\n");
        } while (error);

        // exit the loop and end the program
        if (exit)
        {
            continue;
        }

        // open both input and output files for input and output, respectively
        inFile = fopen(inFileStr, "rb");
        if (inFile == NULL)
        {
            printf("ERROR: could not open input file!\n\n");
            break;
        }
        outFile = fopen(outFileStr, "wb");
        if (outFile == NULL)
        {
            printf("ERROR: could not open output file!\n\n");
            break;
        }

        // If the file is a .bmp, read 54 bytes and write the header to output
        if (strstr(inFileStr, ".BMP") || strstr(inFileStr, ".bmp") || strstr(inFileStr, ".Bmp"))
        {
            bytesR_W = fread(&headerBuffer, 1, sizeof(headerBuffer), inFile); // 54 bytes
            if (bytesR_W < sizeof(headerBuffer))
            {
                perror("ERROR: Unexpected file read error!\n\n");
                break;
            }

            bytesR_W = fwrite(&headerBuffer, 1, sizeof(headerBuffer), outFile);
            if (bytesR_W < sizeof(headerBuffer))
            {
                perror("ERROR: Unexpected file write error!\n\n");
                break;
            }
        }

        bool temp[8] = {false};
        int counter = 0, step = 1;
        
        //Initialize req. for different modes
        switch(op_mode) {
    
            case CBC:
                char inputBuffer[9]; // 8 bits + 1 for null terminator
                printf("Please enter the initialization vector (8 bits) >> ");
                if (scanf("%8s", inputBuffer) != 1) {
                    perror("ERROR: Failed to read initialization vector!\n\n");
                    break;
                }
                getchar(); // to consume the newline character after scanf

                for(int i = 0; i < 8; i++) {
                    if(inputBuffer[i] == '0') {
                        temp[i] = false;
                    } else if(inputBuffer[i] == '1') {
                        temp[i] = true;
                    } else {
                        perror("ERROR: Invalid initialization vector!\n\n");
                    }
                }
                break;
            
            case CTR:
                printf("Enter the starting counter value (0-255) >> ");
                if (scanf("%d", &counter) != 1 || counter < 0 || counter > 255) {
                    perror("ERROR: Invalid counter value!\n\n");
                    break;
                }
                getchar(); // to consume the newline character after scanf
                
                printf("Enter the counter step value (1-255) >> ");
                if (scanf("%d", &step) != 1 || step < 1 || step > 255) {
                    perror("ERROR: Invalid step value!\n\n");
                    printf("INFO: Using default step value of 1.\n");
                    step = 1;
                }
                getchar(); // to consume the newline character after scanf
                break;

            default:
                // Simply do nothing for ECB and CTR modes
                break;
        }

        // read from File
        while (fread(&inputByte, 1, sizeof(inputByte), inFile) > 0)
        {
            outputByte = 0;

            // Read byte to bits
            for (int i = 0; i < 8; i++)
            {
                inputBits[i] = inputByte & (1 << (7 - i));
            }

            
            // Preform SDES function
            if (isE)
            {   
                switch(op_mode) {
                    case ECB:
                        // Implement ECB mode here
                        SDES(inputBits, key, outputBits);
                        break;

                    case CBC:
                        for (int i = 0; i < 8; i++) {
                            inputBits[i] ^= temp[i]; // XOR with IV or previous ciphertext
                        }

                        SDES(inputBits, key, outputBits);

                        for (int i = 0; i < 8; i++) {
                            temp[i] = outputBits[i]; // Update IV with current ciphertext
                        }
                        break;

                    case CTR:
                        
                        // Convert counter to bits
                        for (int i = 0; i < 8; i++) {
                            temp[7 - i] = (counter >> i) & 1;
                        }

                        // Encrypt the counter using SDES
                        SDES(temp, key, outputBits);

                        // XOR the encrypted counter with the input bits
                        for (int i = 0; i < 8; i++) {
                            outputBits[i] ^= inputBits[i];
                        }

                        // Increment the counter
                        counter += step;
                        if (counter > 255) counter = counter % 256; // Wrap around if exceeds 8 bits (256)

                        break;
                    default:
                        // Handle invalid mode
                        break;
                }
            }
            else
            {   
                //Decryption
                switch(op_mode) {
                    case ECB:
                        // Implement ECB mode here
                        SDES_decrypt(inputBits, key, outputBits);
                        break;
                    case CBC:
                        /* Note: Temp[8] stores the IV for the first block, 
                        then the previous ciphertext for subsequent blocks */
                        SDES_decrypt(inputBits, key, outputBits);

                        for (int i = 0; i < 8; i++) {
                            outputBits[i] ^= temp[i]; // XOR with IV or previous ciphertext
                        }

                        for (int i = 0; i < 8; i++) {
                            temp[i] = inputBits[i]; // Update IV with current ciphertext
                        }
                        break;
                    case CTR:
                        // Convert counter to bits
                        for (int i = 0; i < 8; i++) {
                            temp[7 - i] = (counter >> i) & 1;
                        }

                        // Encrypt the counter using SDES
                        SDES(temp, key, outputBits);

                        // XOR the encrypted counter with the input bits
                        for (int i = 0; i < 8; i++) {
                            outputBits[i] ^= inputBits[i];
                        }

                        // Increment the counter
                        counter += step;
                        if (counter > 255) counter = counter % 256; // Wrap around if exceeds 8 bits (256)

                        
                        break;
                    default:
                        // Handle invalid mode
                        printf("ERROR: Invalid operation mode!\n\n");
                        break;
                }
            }

            // Bits to Byte
            for (int i = 0; i < 8; i++)
            {
                if (outputBits[i])
                {
                    outputByte |= (1 << (7 - i));
                }
            }

            printf("Input Byte: %02X -> Output Byte: %02X\n", inputByte, outputByte);

            // Write to file
            bytesR_W = fwrite(&outputByte, 1, sizeof(outputByte), outFile);
            if (bytesR_W < sizeof(outputByte))
            {
                perror("ERROR: Unexpected file write error!\n\n");
                break;
            }
        }

        fclose(inFile);
        fclose(outFile);
    }

    return 0;
}

/***********************************************************************************
*** FUNCTION void ReadInputArgs(char inFileStr[101], bool* isE,                  ***
***          char outFileStr[101], bool key[10], bool* isKey, bool* error,       ***
***          bool* exit)                                                         ***
************************************************************************************
*** DESCRIPTION : This function preforms the decrytion for a 8-bit block of      ***
***               input data.                                                    ***
*** INPUT ARGS : N/A                                                             ***
*** OUTPUT ARGS : char inFileStr[101], bool* isE, char outFileStr[101],          ***
***               bool key[10], bool* isKey, bool* error, bool* exit             ***
*** IN/OUT ARGS : N/A                                                            ***
*** RETURN : N/A                                                                 ***
***********************************************************************************/
void ReadInputArgs(char inFileStr[101], bool *isE, char outFileStr[101], bool key[10], bool *isKey, bool *error, bool *exit)
{
    char inLine[250];
    char rawIsE[2];
    char rawKey[11];
    int numArgs = 0;
    int tooManyArgs = 0;

    // Prompt for Encrypt/Decrypt/Exit
    printf("Enter E for Encryption, D for Decryption, or exit to end program: ");
    fgets(inLine, sizeof(inLine), stdin);
    inLine[strcspn(inLine, "\r\n")] = '\0';
    if (strcmp(inLine, "exit") == 0)
    {
        // exit program condition
        *exit = true;
        return;
    }
    if (sscanf(inLine, "%1s", rawIsE) != 1)
    {
        // Throw an error if no E or D
        *error = true;
        return;
    }

    // Resolve rawIsE argument to isE bool
    if (rawIsE[0] == 'E')
    {
        *isE = true;
    }
    else if (rawIsE[0] == 'D')
    {
        *isE = false;
    }
    else
    {
        *error = true;
        return;
    }

    //get the mode
    printf("Enter mode (ECB, CBC, CTR), or press enter for default (ECB): ");
    fgets(inLine, sizeof(inLine), stdin);
    inLine[strcspn(inLine, "\r\n")] = '\0';
    if (strlen(inLine) == 0)
    {
        // Default mode
        printf("Using deafult mode (ECB).\n");
        op_mode = ECB;
    }
    else if (strcmp(inLine, "ECB") == 0)
    {
        op_mode = ECB;
    }
    else if (strcmp(inLine, "CBC") == 0)
    {
        op_mode = CBC;
    }
    else if (strcmp(inLine, "CTR") == 0)
    {
        op_mode = CTR;
    }
    else
    {
        *error = true;
        return;
    }

    // Prompt for Key (optional)
    printf("Enter 10-bit key (optional, press enter to skip): ");
    fgets(inLine, sizeof(inLine), stdin);
    inLine[strcspn(inLine, "\r\n")] = '\0';
    if (strlen(inLine) > 0)
    {
        // Key is provided
        sscanf(inLine, "%10s", rawKey);
        *isKey = true;
        for (int i = 0; i < 10; i++)
        {
            if (rawKey[i] == '0')
            {
                key[i] = false;
            }
            else if (rawKey[i] == '1')
            {
                key[i] = true;
            }
            else
            {
                *error = true;
                return;
            }
        }
    }

    // Prompt for Input File (optional)
    printf("Enter input file name: ");
    fgets(inLine, sizeof(inLine), stdin);
    inLine[strcspn(inLine, "\r\n")] = '\0';
    if (strlen(inLine) == 0)
    {
        // Default input File
        if (*isE)
            strcpy(inFileStr, "plaintext.txt");
        else
            strcpy(inFileStr, "ciphertext.txt");
    }
    else
    {
        // Input File is provided
        sscanf(inLine, "%100s", inFileStr);
    }

    // Prompt for Output File (optional)
    printf("Enter output file name (optional, press enter to skip): ");
    fgets(inLine, sizeof(inLine), stdin);
    inLine[strcspn(inLine, "\r\n")] = '\0';
    if (strlen(inLine) == 0)
    {
        // Default input File
        if (*isE)
            strcpy(outFileStr, "ciphertext.txt");
        else
            strcpy(outFileStr, "plaintext.txt");
    }
    else
    {
        // Input File is provided
        sscanf(inLine, "%100s", outFileStr);
    }
}