#include <stdio.h>
#include <stdlib.h>

#include "UtilFunction.h"
#include "DiffHellman.h"
#include "certs.h"

int main() {
    
    unsigned int p, q;
    unsigned int e = 0;
    unsigned int d = 0;

    do{

        printf("Generating RSA key pair...\n");
        printf("Enter two prime numbers (p and q): ");
        scanf("%u %u", &p, &q);
        getchar(); // consume newline left by scanf

        if(isPrime(p) && isPrime(q)){
            d = RSA_KeyGen(p, q, &e);
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
    
    certGen(d, e); 

    return 0;
}