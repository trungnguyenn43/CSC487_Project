#include <stdio.h>
#include <stdlib.h>

#include "UtilFunction.h"
#include "DiffHellman.h"
#include "certs.h"

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
    
    do{
        // create menu
        char inputBuffer[10];
        int choice = 0;
        printf("Please select an option:\n");
        printf("1. Generate Certificate\n");
        printf("2. Verify Certificate\n");
        printf("3. Exit\n");
        printf("Enter choice >> ");
        fgets(inputBuffer, sizeof(inputBuffer), stdin);
        choice = atoi(inputBuffer);

        switch(choice){
            case 1:
                certGen(d, e, n); // pass private, public key, and n
                break;
            case 2:
                certVerify();
                break;
            case 3:
                printf("Exiting program.\n");
                return 0;
            default:
                break;
        }
    }while(1);
    

    return 0;
}