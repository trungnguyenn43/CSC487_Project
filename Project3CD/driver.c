#include <stdio.h>
#include <stdlib.h>

#include "UtilFunction.h"
#include "DiffHellman.h"
#include "certs.h"

const char CRL_FILE_NAME[] = "crl_list.txt";

int main() {
    
    unsigned int p, q;
    unsigned int e = 0;
    unsigned int d = 0;
    unsigned int n = 0;

    do{

        printf("Generating RSA key pair...\n");
        printf("Enter two prime numbers (p and q): ");
        scanf("%u %u", &p, &q);
        getchar(); // consume newline left by scanf

        if(isPrime(p) && isPrime(q)){
            d = RSA_KeyGen(p, q, &e);
            n = p * q;
            printf("Public key (e): %u\n", e);
            printf("Private key (d): %u\n", d);
            printf("========================================\n\n");
            break;
        }
        else{
            if(gcd(p, q) != 1){
                printf("p and q are not coprime. Continue...\n\n");
                continue;
            }
            printf("Either p or q is not prime. Please enter again.\n\n");
        }
        
        continue;
        
    }while(1);

    // Project 3B: CRL
    FILE *crlFile = fopen(CRL_FILE_NAME, "a+");
    if (crlFile == NULL)
    {
        printf("Error opening CRL file.\n");
        return -1;
    }
    fclose(crlFile);

    char* certList[100];
    
    char fileName[100] = "";
    crlInfo crlFileInfo;
    crlEntry crlEntries[100];

    printf("Enter CRL file name or press enter to use default (default: crl_list.txt): ");
    fgets(fileName, sizeof(fileName), stdin);
    // remove newline character from fgets
    fileName[strcspn(fileName, "\n")] = 0;
    if(strlen(fileName) == 0){
        printf("Using default CRL file name: %s\n", CRL_FILE_NAME);
        strcpy(crlFileInfo.crlFileName, CRL_FILE_NAME);
    }
    else{
        printf("Using CRL file name: %s\n", fileName);
        strcpy(crlFileInfo.crlFileName, fileName);
    }
    if(loadCRLEntry(&crlFileInfo, crlEntries, d, e, n) != 1){
        printf("Load CRL entries failed. Exiting program!\n");
        return -1;
    }
    
    do{
        // create menu
        char inputBuffer[10];
        int choice = 0;
        printf("Please select an option:\n");
        printf("1. Generate Certificate\n");
        printf("2. Verify Certificate\n");
        printf("3. Add revoked cert\n");
        printf("4. Remove revoked cert\n");
        printf("5. Show CRL List\n");
        printf("6. New CRL File\n");
        printf("7. Exit\n");
        printf("Enter choice >> ");
        fgets(inputBuffer, sizeof(inputBuffer), stdin);
        choice = atoi(inputBuffer);

        switch(choice){
            case 1:
                certGen(d, e, n); // pass private, public key, and n
                break;
            case 2:
                certVerify(crlEntries, crlFileInfo.numEntries);
                break;
            case 3:
                addCRLEntry(crlEntries, &crlFileInfo.numEntries);
                saveCRL(&crlFileInfo, crlEntries, d, e, n);
                break;
            case 4:
                printf("Enter Certificate Serial Number to remove from CRL: ");
                fgets(inputBuffer, sizeof(inputBuffer), stdin);
                // remove newline character from fgets
                inputBuffer[strcspn(inputBuffer, "\n")] = 0;
                rmCRLEntry(crlEntries, &crlFileInfo.numEntries, inputBuffer);
                break;
            case 5:
                if(crlFileInfo.numEntries == 0){
                    printf("CRL list is empty.\n");
                    printf("===========================================\n\n");

                    break;
                }
                printf("============== CRL ENTRY ===================\n");
                printf("Total revoked certificates: %d\n", crlFileInfo.numEntries);
                for(int i = 0; i < crlFileInfo.numEntries; i++){
                    printf("%4d. Serial Number: %s, Revocation Date: %s", i, crlEntries[i].serialNumber, ctime(&crlEntries[i].revocationDate));
                }
                printf("===========================================\n\n");
                break;
            
            case 6:
                printf("Enter new CRL file name: ");
                fgets(fileName, sizeof(fileName), stdin);
                // remove newline character from fgets
                fileName[strcspn(fileName, "\n")] = 0;
                strcpy(crlFileInfo.crlFileName, fileName);
                crlFileInfo.numEntries = 0; // reset number of entries
                printf("New CRL file set to: %s\n", crlFileInfo.crlFileName);
                newCRLFile(crlFileInfo.crlFileName, d, e, n);
                break;
            
            case 7:
                printf("Exiting program.\n");
                saveCRL(&crlFileInfo, crlEntries, d, e, n);
                return 0;
            default:
                break;
        }
    }while(1);
    

    return 0;
}