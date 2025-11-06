
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "UtilFunction.h"
#include "DiffHellman.h"
#include "certs.h"

const int VALID_DURATION_SECONDS = 24 * 60 * 60; // 1 day
const char IV[3] = "1A";

void certGen(unsigned int privateKey, unsigned int publicKey){

    char inputBuffer[256];
    char valueString[1024] = ""; // string temp to hold all cert values for signing

    // file name
    printf("Enter output certificate file name: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    // remove newline character from fgets
    inputBuffer[strcspn(inputBuffer, "\n")] = 0;

    FILE *certFile = fopen(inputBuffer, "w");
    if(certFile == NULL){
        printf("Error opening certificate file for writing.\n");
        return;
    }

    //get information from user
    fprintf(certFile, "-----BEGIN CERTIFICATE-----\n");
    
    //need: version, cert serial #, algorithm, parameters, 
    //issuer name, not before, not after, subject name
    //algorithm, parameters, public key, signature

    // Version
    printf("Enter Version: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Version:\n%s", inputBuffer);
    strcat(valueString, inputBuffer);

    // Certificate Serial Number
    printf("Enter Certificate Serial Number: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Certificate Serial Number:\n%s", inputBuffer);
    strcat(valueString, inputBuffer);

    // Algorithm
    printf("Enter Algorithm: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Algorithm:\n%s", inputBuffer);
    strcat(valueString, inputBuffer);

    // Parameters
    printf("Enter Parameters: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Parameters:\n%s", inputBuffer);
    strcat(valueString, inputBuffer);

    // Issuer Name
    printf("Enter Issuer Name: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Issuer Name:\n%s", inputBuffer);
    strcat(valueString, inputBuffer);

    // Validity Period
    time_t validFromTime = time(NULL);
    time_t expireTime = validFromTime + VALID_DURATION_SECONDS;
    // Not Before
    fprintf(certFile, "Not Before:\n%s", ctime(&validFromTime));
    strcat(valueString, ctime(&validFromTime));
    // Not After
    fprintf(certFile, "Not After:\n%s", ctime(&expireTime));
    strcat(valueString, ctime(&expireTime));

    // Subject Name
    printf("Enter Subject Name: ");
    fgets(inputBuffer, sizeof(inputBuffer), stdin);
    fprintf(certFile, "Subject Name:\n%s", inputBuffer);
    strcat(valueString, inputBuffer);

    // Public Key
    fprintf(certFile, "Public Key:\n%u\n", publicKey);
    sprintf(inputBuffer, "%u", publicKey);
    strcat(valueString, inputBuffer);

    // Signature
    // Sign the valueString using privateKey
    char KEY[4];
    // integer to hexs string
    sprintf(KEY, "%03X", privateKey);
    
    CBCHash(valueString, IV, KEY, inputBuffer);
    fprintf(certFile, "Signature:\n%s\n", inputBuffer);

    fclose(certFile);
    
}

void certVerify(unsigned int publicKey){
    
}