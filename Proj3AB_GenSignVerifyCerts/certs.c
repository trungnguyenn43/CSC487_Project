
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "UtilFunction.h"
#include "DiffHellman.h"
#include "certs.h"

const int VALID_DURATION_SECONDS = 24 * 60 * 60; // 1 day
static char IV[3] = "1A";
static char CBC_KEY[4] = "B2C";

void certGen(unsigned int privateKey, unsigned int publicKey, unsigned int n)
{

    char inputBuffer[256];
    char fileName[100];

    // file name
    printf("Enter output certificate file name: ");
    fgets(fileName, sizeof(fileName), stdin);
    // remove newline character from fgets
    fileName[strcspn(fileName, "\n")] = 0;

    FILE *certFile = fopen(fileName, "w");
    if (certFile == NULL)
    {
        printf("Error opening certificate file for writing.\n");
        return;
    }

    // get information from user

    // need: version, cert serial #, algorithm, parameters,
    // issuer name, not before, not after, subject name
    // algorithm, parameters, public key, signature

    // Version
    printf("Enter Version: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Version: %s", inputBuffer);

    // Certificate Serial Number
    printf("Enter Certificate Serial Number: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Certificate Serial Number: %s", inputBuffer);

    // Level of trust
    printf("Enter Level of Trust: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Level of Trust: %s", inputBuffer);

    // Algorithm
    printf("Enter Algorithm: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Algorithm: %s", inputBuffer);

    // Parameters
    printf("Enter Parameters: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Parameters: %s", inputBuffer);

    // Issuer Name
    printf("Enter Issuer Name: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Issuer Name: %s", inputBuffer);

    // Validity Period
    time_t validFromTime = time(NULL);
    time_t expireTime = validFromTime + VALID_DURATION_SECONDS;
    // Not Before
    fprintf(certFile, "Not Before: %ld\n", validFromTime);
    // Not After
    fprintf(certFile, "Not After: %ld\n", expireTime);

    // Subject Name
    printf("Enter Subject Name: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Subject Name: %s", inputBuffer);

    // Public Key
    fprintf(certFile, "Public Key: %u %u\n", publicKey, n);
    sprintf(inputBuffer, "%u %u\n", publicKey, n);

    fclose(certFile);

    // Signature
    char valueString[1024] = ""; // string temp to hold all cert values for signing
    memset(valueString, '\0', sizeof(valueString));

    // reopen file to read values for signing
    certFile = fopen(fileName, "r+");
    if (certFile == NULL)
    {
        printf("Error opening certificate file for reading.\n");
        return;
    }

    while(fgets(inputBuffer, sizeof(inputBuffer), certFile) != NULL)
    {
        strcat(valueString, inputBuffer);
    }

    printf("%s", valueString);
    
    char computedHash[3] ={'\0'};

    CBCHash(valueString, IV, CBC_KEY, computedHash);

    unsigned int hashValue = (unsigned int)strtol(computedHash, NULL, 16); // convert hash to integer

    // append signature to end of file
    fprintf(certFile, "Signature: %d\n", modExp(hashValue, privateKey, n));

    fclose(certFile);
}

int certVerify()
{

    char inputBuffer[256];
    char valueString[1024]; // string temp to hold all cert values for signing
    memset(valueString, '\0', sizeof(valueString));

    char publicKeyStr[5];
    unsigned int certSignature;
    unsigned int publicKey;
    unsigned int n;

    // file name
    printf("Enter certificate file name to verify: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    // remove newline character from fgets
    inputBuffer[strcspn(inputBuffer, "\n")] = 0;

    FILE *certFile = fopen(inputBuffer, "r");
    if (certFile == NULL)
    {
        printf("Error opening certificate file for reading.\n");
        return -1;
    }

    while (fgets(inputBuffer, sizeof(inputBuffer), certFile) != NULL)
    {
        if (strncmp(inputBuffer, "Signature:", 10) == 0)
        {
            // extract signature
            sscanf(inputBuffer, "Signature: %u", &certSignature);
        }
        else if (strncmp(inputBuffer, "Public Key:", 11) == 0)
        {
            // extract public key and n
            sscanf(inputBuffer, "Public Key: %u %u", &publicKey, &n);
            // append to valueString
            strcat(valueString, inputBuffer);
        }
        else
        {
            // append other lines to valueString
            strcat(valueString, inputBuffer);
        }
    }

    fclose(certFile);

    printf("certSignature: %u\n", certSignature);
    printf("Public Key: %u\n", publicKey);
    printf("N: %u\n", n);

    //Veriy signature
    char computedHash[3] = {'\0'};

    CBCHash(valueString, IV, CBC_KEY, computedHash);

    unsigned int hashValue = (unsigned int)strtol(computedHash, NULL, 16); // convert hash to integer
    
    unsigned int decryptedSignature = modExp(certSignature, publicKey, n);

    printf("Computed Hash Value: %u\n", hashValue);
    printf("Decrypted Signature: %u\n", decryptedSignature);

    // Compare signatures
    if (decryptedSignature == hashValue)
    {
        printf("Certificate is valid.\n");
        return 1;
    }
    else
    {
        printf("Certificate is invalid.\n");
        return 0;
    }
}