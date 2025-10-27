
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "UtilFunction.h"
#include "DiffHellman.h"

int main(){

    unsigned int p;
    unsigned int q;
    unsigned int n;

    do{
        printf("Enter two prime numbers (p and q): ");
        scanf("%u %u", &p, &q);
        n = p * q;

        if(gcd(p, q) != 1){
            printf("p and q are not coprime. Please enter again.\n");
        } else {
            printf("p and q are coprime. Continue...\n\n");
            break;
        }
        
    } while(1); // ensure p and q are coprime

    unsigned int totient_n = (p - 1) * (q - 1);

    unsigned int e = 0;
    unsigned int d = RSA_KeyGen(p, q, &e);
    printf("Your q: %u, p: %u, n: %u\n", p, q, n);
    printf("Totient(n): %u\n", totient_n);
    printf("Public e: %u\n", e);
    printf("Private d: %u\n", d);

    printf("========================================\n\n");

    do{

        int mode = -1;
        printf("Select mode:\n");
        printf("1: RSA Encrypt  message\n");
        printf("2. RSA Descrypt  Message\n");
        printf("3: Exit\n");
        printf(">> ");
        scanf("%d", &mode);

        if(mode == 3){
            break;
        } else if(mode > 1 || mode < 2){
            printf("Invalid mode. Please enter again.\n");
            continue;
        }

        switch(mode){
            case 1: {
                unsigned int message;
                printf("Enter message (as an integer < %u): ", n);
                scanf("%u", &message);
                if(message >= n){
                    printf("Message must be less than n (%u). Please enter again.\n", n);
                    break;
                }
                // Encrypt message
                unsigned int cipher = modExp(message, e, n);
                printf("Encrypted message (cipher): %u\n\n", cipher);
                break;
            }
            case 2: {
                unsigned int cipher;
                printf("Enter cipher (as an integer < %u): ", n);
                scanf("%u", &cipher);
                if(cipher >= n){
                    printf("Cipher must be less than n (%u). Please enter again.\n", n);
                    break;
                }
                // Decrypt message
                unsigned int message = modExp(cipher, d, n);
                printf("Decrypted message: %u\n\n", message);
                break;
            }
            default:
                printf("Invalid mode. Please enter again.\n");
                break;
        }
        
    }while(1);
    
    return 0;
}