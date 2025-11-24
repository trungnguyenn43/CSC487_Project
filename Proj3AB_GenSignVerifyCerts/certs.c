
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "UtilFunction.h"
#include "DiffHellman.h"
#include "certs.h"

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
    do{
        printf("Enter Level of Trust (0-7): ");
        fgets(inputBuffer, sizeof(inputBuffer), stdin);
        
        int level = -1;
        if(sscanf(inputBuffer, "%d", &level) != 1){
            printf("Invalid input. Please enter again.\n");
            continue;
        }
        
        if(level >=0 && level <=7){
            fprintf(certFile, "Level of Trust: %s", inputBuffer);
            break;
        }
        else{
            printf("Invalid level of trust. Please enter again.\n");
        }
        
    }while(1);
    

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
    time_t expireTime = validFromTime;
    // Not Before
    fprintf(certFile, "Not Before: %ld\n", validFromTime);
    
    print("Enter valid duration (in seconds): ")
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    int validDuration;
    if(sscanf(inputbuffer, "%d", &validDuration)){
        expireTime = validFromTime + validDuration;
    }else{
        printf("Invalid input. Use default duration of 1 day.\n");
        expireTime = validFromTime + VALID_DURATION_SECONDS;
    }
    // Not After
    fprintf(certFile, "Not After: %ld\n", expireTime);

    // Subject Name
    printf("Enter Subject Name: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Subject Name: %s", inputBuffer);

    fclose(certFile);

    // Sign the certificate
    signFile(fileName, privateKey, publicKey, n);

    printf("Certificate %s generated and signed successfully.\n", fileName);
    printf("=================================\n\n");
}

int certVerify(const crlEntry entryList[], int numEntries)
{   
    char inputBuffer[256];
    char fileName[256];
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
    strcpy(fileName, inputBuffer);

    if(verifyFileSignature(fileName) != 1){
        printf("=================================\n\n");
        return -1;
    };

    FILE *certFile = fopen(inputBuffer, "r");
    if (certFile == NULL)
    {
        printf("Error opening certificate file for reading.\n");
        fclose(certFile);
        return -1;
    }
    fseek(certFile, 0, SEEK_SET); // move pointer to beginning of file

    time_t currentTime = time(NULL);
    time_t notBefore, notAfter;
    while(fgets(inputBuffer, sizeof(inputBuffer), certFile) != NULL)
    {   
        if(strncmp(inputBuffer, "Certificate Serial Number:", 26) == 0)
        {   
            inputBuffer[strcspn(inputBuffer, "\n")] = 0;
            // extract serial number
            char serialNumber[256];
            sscanf(inputBuffer, "Certificate Serial Number: %s", serialNumber);
            
            // check if serial number is in CRL
            for(int i = 0; i < numEntries; i++){
                if(strcmp(serialNumber, entryList[i].serialNumber) == 0){
                    printf("Certificate with Serial Number %s is revoked.\n", serialNumber);
                    printf("=================================\n\n");
                    fclose(certFile);
                    return 0;
                }
            }
            
            printf("Certificate is not revoked.\n");
            
        }
        else if (strncmp(inputBuffer, "Not Before:", 11) == 0)
        {
            // extract not before time
            sscanf(inputBuffer, "Not Before: %ld", &notBefore);
        }
        else if (strncmp(inputBuffer, "Not After:", 10) == 0)
        {
            // extract not after time
            sscanf(inputBuffer, "Not After: %ld", &notAfter);
            break; // no need to read further
        }

    }

    if(currentTime < notBefore){
        printf("Certificate is not yet valid.\n\n");
        fclose(certFile);
        return 0;
    }
    else if(currentTime > notAfter){
        printf("Certificate has expired.\n\n");
        fclose(certFile);
        return 0;
    }
    else{
        printf("Certificate is within the validity period.\n");
    }

    printf("Certificate is valid.\n");
    printf("=================================\n\n");
    
    fclose(certFile);
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