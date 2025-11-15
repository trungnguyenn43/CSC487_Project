#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "UtilFunction.h"
#include "DiffHellman.h"
#include "certs.h"

static char IV[3] = "1A";
static char CBC_KEY[4] = "B2C";

struct certInfo{
    char version[256];
    char serialNumber[256];
    int levelOfTrust;
    char algorithm[50];
    char parameters[100];
    char issuerName[100];
    time_t notBefore;
    time_t notAfter;
    char subjectName[100];
    unsigned int publicKey;
    unsigned int n;
    unsigned int signature;
};


void certGen(unsigned int privateKey, unsigned int publicKey, unsigned int n)
{
    struct certInfo cert;
    char inputBuffer[256];
    char fileName[100];

    // file name
    printf("Enter output certificate file name: ");
    fgets(fileName, sizeof(fileName), stdin);
    fileName[strcspn(fileName, "\n")] = 0;

    FILE *certFile = fopen(fileName, "w");
    if (certFile == NULL)
    {
        printf("Error opening certificate file for writing.\n");
        return;
    }

    // Populate certInfo struct
    printf("Enter Version: ");
    fgets(cert.version, sizeof(cert.version), stdin);
    cert.version[strcspn(cert.version, "\n")] = 0;

    printf("Enter Certificate Serial Number: ");
    fgets(cert.serialNumber, sizeof(cert.serialNumber), stdin);
    cert.serialNumber[strcspn(cert.serialNumber, "\n")] = 0;

    do {
        printf("Enter Level of Trust (0-7): ");
        fgets(inputBuffer, sizeof(inputBuffer), stdin);
        if (sscanf(inputBuffer, "%d", &cert.levelOfTrust) == 1 && cert.levelOfTrust >= 0 && cert.levelOfTrust <= 7)
            break;
        printf("Invalid input. Please enter again.\n");
    } while (1);

    printf("Enter Algorithm: ");
    fgets(cert.algorithm, sizeof(cert.algorithm), stdin);
    cert.algorithm[strcspn(cert.algorithm, "\n")] = 0;

    printf("Enter Parameters: ");
    fgets(cert.parameters, sizeof(cert.parameters), stdin);
    cert.parameters[strcspn(cert.parameters, "\n")] = 0;

    printf("Enter Issuer Name: ");
    fgets(cert.issuerName, sizeof(cert.issuerName), stdin);
    cert.issuerName[strcspn(cert.issuerName, "\n")] = 0;

    cert.notBefore = time(NULL);
    printf("Enter valid duration (in seconds): ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    int validDuration;
    if (sscanf(inputBuffer, "%d", &validDuration))
        cert.notAfter = cert.notBefore + validDuration;
    else
        cert.notAfter = cert.notBefore + VALID_DURATION_SECONDS;

    printf("Enter Subject Name: ");
    fgets(cert.subjectName, sizeof(cert.subjectName), stdin);
    cert.subjectName[strcspn(cert.subjectName, "\n")] = 0;

    cert.publicKey = publicKey;
    cert.n = n;

    // Write certInfo to file
    fprintf(certFile, "Version: %s\n", cert.version);
    fprintf(certFile, "Certificate Serial Number: %s\n", cert.serialNumber);
    fprintf(certFile, "Level of Trust: %d\n", cert.levelOfTrust);
    fprintf(certFile, "Algorithm: %s\n", cert.algorithm);
    fprintf(certFile, "Parameters: %s\n", cert.parameters);
    fprintf(certFile, "Issuer Name: %s\n", cert.issuerName);
    fprintf(certFile, "Not Before: %ld\n", cert.notBefore);
    fprintf(certFile, "Not After: %ld\n", cert.notAfter);
    fprintf(certFile, "Subject Name: %s\n", cert.subjectName);

    fclose(certFile);

    // Sign the certificate
    signFile(fileName, privateKey, publicKey, n);

    printf("Certificate %s generated and signed successfully.\n", fileName);
    printf("=================================\n\n");
}

int certVerify(const crlEntry entryList[], int numEntries)
{
    struct certInfo cert;
    char inputBuffer[256];
    char fileName[256];

    printf("Enter certificate file name to verify: ");
    fgets(fileName, sizeof(fileName), stdin);
    fileName[strcspn(fileName, "\n")] = 0;

    if (verifyFileSignature(fileName) != 1)
    {
        printf("=================================\n\n");
        return -1;
    }

    FILE *certFile = fopen(fileName, "r");
    if (certFile == NULL)
    {
        printf("Error opening certificate file for reading.\n");
        return -1;
    }

    // Read certInfo from file
    while (fgets(inputBuffer, sizeof(inputBuffer), certFile) != NULL)
    {
        if (strncmp(inputBuffer, "Version:", 8) == 0)
            sscanf(inputBuffer, "Version: %255[^\n]", cert.version);
        else if (strncmp(inputBuffer, "Certificate Serial Number:", 26) == 0)
            sscanf(inputBuffer, "Certificate Serial Number: %255[^\n]", cert.serialNumber);
        else if (strncmp(inputBuffer, "Level of Trust:", 15) == 0)
            sscanf(inputBuffer, "Level of Trust: %d", &cert.levelOfTrust);
        else if (strncmp(inputBuffer, "Algorithm:", 10) == 0)
            sscanf(inputBuffer, "Algorithm: %49[^\n]", cert.algorithm);
        else if (strncmp(inputBuffer, "Parameters:", 11) == 0)
            sscanf(inputBuffer, "Parameters: %99[^\n]", cert.parameters);
        else if (strncmp(inputBuffer, "Issuer Name:", 12) == 0)
            sscanf(inputBuffer, "Issuer Name: %99[^\n]", cert.issuerName);
        else if (strncmp(inputBuffer, "Not Before:", 11) == 0)
            sscanf(inputBuffer, "Not Before: %ld", &cert.notBefore);
        else if (strncmp(inputBuffer, "Not After:", 10) == 0)
            sscanf(inputBuffer, "Not After: %ld", &cert.notAfter);
        else if (strncmp(inputBuffer, "Subject Name:", 13) == 0)
            sscanf(inputBuffer, "Subject Name: %99[^\n]", cert.subjectName);
    }

    fclose(certFile);

    // Verify certificate validity
    time_t currentTime = time(NULL);
    if (currentTime < cert.notBefore)
    {
        printf("Certificate is not yet valid.\n\n");
        return 0;
    }
    else if (currentTime > cert.notAfter)
    {
        printf("Certificate has expired.\n\n");
        return 0;
    }

    // Check if serial number is in CRL
    for (int i = 0; i < numEntries; i++)
    {
        if (strcmp(cert.serialNumber, entryList[i].serialNumber) == 0)
        {
            printf("Certificate with Serial Number %s is revoked.\n", cert.serialNumber);
            return 0;
        }
    }

    printf("Certificate is valid.\n");
    printf("=================================\n\n");
    return 1;
}

void signFile(char fileName[], unsigned int privateKey, unsigned int publicKey, unsigned int n){
    char inputBuffer[256];

    // file name check
    if(strlen(fileName) == 0){
        printf("Error: File name is empty.\n");
        return;
    }

    FILE *certFile = fopen(fileName, "r+");
    if (certFile == NULL)
    {
        printf("Error opening file for signing.\n");
        return;
    }

    fseek(certFile, 0, SEEK_SET); // move pointer to beginning of file
    
    char fileContent[1024];
    memset(fileContent, '\0', sizeof(fileContent));

    while(fgets(inputBuffer, sizeof(inputBuffer), certFile) != NULL)
    {   
        strcat(fileContent, inputBuffer);
    }
    
    fseek(certFile, 0, SEEK_END); // move pointer to EOF
    fprintf(certFile, "\n");
    strcat(fileContent, "\n"); // include the newline in the content to be hashed
    fprintf(certFile, "Public Key: %u %u\n", publicKey, n);
    snprintf(inputBuffer, sizeof(inputBuffer), "Public Key: %u %u\n", publicKey, n);
    strcat(fileContent, inputBuffer); // include public key line in content to be hashed

    char computedHash[3] = {'\0'};
    CBCHash(fileContent, IV, CBC_KEY, computedHash);

    unsigned int hashValue = (unsigned int)strtol(computedHash, NULL, 16); // convert hash to integer

    //write to the end of file
    fprintf(certFile, "Signature: %d\n", modExp(hashValue, privateKey, n));

    fclose(certFile);
}

int verifyFileSignature(char fileName[]){
    char inputBuffer[256];
    unsigned int publicKey, n;
    unsigned int certSignature;

    // file name check
    if(strlen(fileName) == 0){
        printf("Error: File name is empty.\n");
        return -1;
    }

    FILE *certFile = fopen(fileName, "r");
    if (certFile == NULL)
    {
        printf("Error opening file for signature verification.\n");
        return -1;
    }
    
    char fileContent[1024];
    memset(fileContent, '\0', sizeof(fileContent));
    
    fseek(certFile, 0, SEEK_SET); // move pointer to beginning of file

    while(fgets(inputBuffer, sizeof(inputBuffer), certFile) != NULL)
    {      
        if(strncmp(inputBuffer, "Signature:", 10) == 0)
        {
            // extract signature
            sscanf(inputBuffer, "Signature: %u", &certSignature);
        }
        else if (strncmp(inputBuffer, "Public Key:", 11) == 0)
        {
            // extract public key and n
            sscanf(inputBuffer, "Public Key: %u %u", &publicKey, &n);
            // append to valueString
            strcat(fileContent, inputBuffer);
        }
        else
        {
            // append other lines to valueString
            strcat(fileContent, inputBuffer);
        }
    }

    fclose(certFile);

    char computedHash[3];
    CBCHash(fileContent, IV, CBC_KEY, computedHash);

    unsigned int hashValue = (unsigned int)strtol(computedHash, NULL, 16); // convert hash to integer
    unsigned int decryptedSignature = modExp(certSignature, publicKey, n);

    // Compare signatures
    if (decryptedSignature == hashValue)
    {
        printf("File %s signature is valid.\n", fileName);
        return 1;
    }
    else
    {
        printf("File %s signature is invalid.\n", fileName);
        return 0;
    }

}

void addCRLEntry(crlEntry entryList[], int *numEntries)
{   
    char inputBuffer[256];
    printf("Enter Certificate Serial Number to revoke: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    // remove newline character from fgets
    inputBuffer[strcspn(inputBuffer, "\n")] = 0;

    strcpy(entryList[*numEntries].serialNumber, inputBuffer);
    entryList[*numEntries].revocationDate = time(NULL);
    (*numEntries)++;

    printf("Certificate with Serial Number %s added to CRL.\n", inputBuffer);
    printf("=================================\n\n");
}

void rmCRLEntry(crlEntry entryList[], int *numEntries, const char serialNumber[])
{
    int foundIndex = -1;
    for (int i = 0; i < *numEntries; i++)
    {
        if (strcmp(entryList[i].serialNumber, serialNumber) == 0)
        {
            foundIndex = i;
            break;
        }
    }

    if (foundIndex != -1)
    {
        // Shift entries to remove the found entry
        for (int i = foundIndex; i < *numEntries - 1; i++)
        {
            entryList[i] = entryList[i + 1];
        }
        (*numEntries)--;
        printf("Certificate with Serial Number %s removed from CRL.\n", serialNumber);
    }
    else
    {
        printf("Certificate with Serial Number %s not found in CRL.\n", serialNumber);
    }

    printf("=================================\n\n");
}

int loadCRLEntry(crlInfo *crlFileInfo, crlEntry entryList[], unsigned int privateKey, unsigned int publicKey, unsigned int n)
{   
    // file name check
    if(strlen(crlFileInfo->crlFileName) == 0){
        printf("Error: CRL file name is empty.\n");
        return -2;
    }

    FILE *crlFile;
    crlFile = fopen(crlFileInfo->crlFileName, "r");
    
    if (crlFile == NULL)
    {
        printf("CRL file not found. Creating a new CRL file.\n");
        *crlFileInfo = newCRLFile(crlFileInfo->crlFileName, privateKey, publicKey, n);
        crlFileInfo->numEntries = 0;
        return 1;
    }

    // Check if the file is empty
    fseek(crlFile, 0, SEEK_END);
    if (ftell(crlFile) == 0)
    {
        printf("CRL file is empty. Creating a new CRL file.\n");
        fclose(crlFile);
        *crlFileInfo = newCRLFile(crlFileInfo->crlFileName, privateKey, publicKey, n);
        crlFileInfo->numEntries = 0;
        return 1;
    }
    fseek(crlFile, 0, SEEK_SET); // Reset file pointer to the beginning


    if(verifyFileSignature(crlFileInfo->crlFileName) != 1){
        printf("Authentication failed!\n");
        fclose(crlFile);
        return -1;
    }

    char inputBuffer[256];
    // read CRL info
    fgets(inputBuffer, sizeof(inputBuffer), crlFile);
    sscanf(inputBuffer, "Algorithm: %s", crlFileInfo->algorithm);
    fgets(inputBuffer, sizeof(inputBuffer), crlFile);
    sscanf(inputBuffer, "Parameters: %s", crlFileInfo->parameters);
    fgets(inputBuffer, sizeof(inputBuffer), crlFile);
    sscanf(inputBuffer, "Issuer Name: %s", crlFileInfo->issuerName);
    fgets(inputBuffer, sizeof(inputBuffer), crlFile);
    sscanf(inputBuffer, "This Update: %ld", &crlFileInfo->thisUpdate);
    fgets(inputBuffer, sizeof(inputBuffer), crlFile);
    sscanf(inputBuffer, "Next Update: %ld", &crlFileInfo->nextUpdate);

    while (fgets(inputBuffer, sizeof(inputBuffer), crlFile) != NULL)
    {   
        struct crlEntry entry;
        if (strncmp(inputBuffer, "Entry:", 6) == 0)
        {
            // read the next line for entry details
            fgets(inputBuffer, sizeof(inputBuffer), crlFile);
            sscanf(inputBuffer, "%s %ld", entry.serialNumber, &entry.revocationDate);
            entryList[crlFileInfo->numEntries] = entry;
            crlFileInfo->numEntries++;
        }
        
    }

    printf("Loaded %d CRL entries from file.\n\n", crlFileInfo->numEntries);
    printf("=================================\n");

    fclose(crlFile);
    return 1;
}

void saveCRL(crlInfo *crlFileInfo, crlEntry entryList[], unsigned int privateKey, unsigned int publicKey, unsigned int n)
{   
    char inputBuffer[256];

    if(strlen(crlFileInfo->crlFileName) == 0){
        printf("Error: CRL file name is empty.\n");
        return;
    }

    FILE *crlFile = fopen(crlFileInfo->crlFileName, "w");
    if (crlFile == NULL)
    {
        printf("Error opening CRL file for writing.\n");
        return;
    }

    crlFileInfo->thisUpdate = time(NULL);
    crlFileInfo->nextUpdate = crlFileInfo->thisUpdate + VALID_DURATION_SECONDS;

    // write CRL info
    fprintf(crlFile, "Algorithm: %s\n", crlFileInfo->algorithm);
    fprintf(crlFile, "Parameters: %s\n", crlFileInfo->parameters);
    fprintf(crlFile, "Issuer Name: %s\n", crlFileInfo->issuerName);
    fprintf(crlFile, "This Update: %ld\n", crlFileInfo->thisUpdate);
    fprintf(crlFile, "Next Update: %ld\n", crlFileInfo->nextUpdate);
    
    for (int i = 0; i < crlFileInfo->numEntries; i++)
    {
        fprintf(crlFile, "Entry:\n");
        fprintf(crlFile, "%s %ld\n", entryList[i].serialNumber, entryList[i].revocationDate);
    }

    fclose(crlFile);

    signFile(crlFileInfo->crlFileName, privateKey, publicKey, n);
}

crlInfo newCRLFile(char crlFileName[], unsigned int privateKey, unsigned int publicKey, unsigned int n)
{   
    char inputBuffer[256];
    crlInfo newCRL;

    FILE *crlFile = fopen(crlFileName, "w");
    if (crlFile == NULL)
    {
        printf("Error creating new CRL file.\n");
        return newCRL;
    }

    // get information from user
    // need: algorithm, parameters, issuer name, this update date, next update date, entries
    printf("Enter Algorithm for CRL: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    inputBuffer[strcspn(inputBuffer, "\n")] = 0;
    fprintf(crlFile, "Algorithm: %s\n", inputBuffer);
    strcpy(newCRL.algorithm, inputBuffer);

    printf("Enter Parameters for CRL: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    inputBuffer[strcspn(inputBuffer, "\n")] = 0;
    fprintf(crlFile, "Parameters: %s\n", inputBuffer);
    strcpy(newCRL.parameters, inputBuffer);


    printf("Enter Issuer Name for CRL: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    inputBuffer[strcspn(inputBuffer, "\n")] = 0;
    fprintf(crlFile, "Issuer Name: %s\n", inputBuffer);
    strcpy(newCRL.issuerName, inputBuffer);

    time_t thisUpdate = time(NULL);
    time_t nextUpdate = thisUpdate + VALID_DURATION_SECONDS;
    fprintf(crlFile, "This Update: %ld\n", thisUpdate);
    fprintf(crlFile, "Next Update: %ld\n", nextUpdate);

    fclose(crlFile);

    strcpy(newCRL.crlFileName, crlFileName);
    newCRL.thisUpdate = thisUpdate;
    newCRL.nextUpdate = nextUpdate;
    newCRL.numEntries = 0;

    signFile(crlFileName, privateKey, publicKey, n);
    printf("New CRL file %s created and signed successfully.\n", crlFileName);
    printf("=================================\n\n");
    return newCRL;
}