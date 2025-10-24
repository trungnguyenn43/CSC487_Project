
#include <stdio.h>
#include <stdlib.h>

#include "UtilFunction.h"

int multiplicativeInverse(unsigned int n, unsigned int totient, unsigned int x){

    int x1, y1; // To store results of extendedEuclidean

    // if gcd(x, totient) != 1, multiplicative inverse doesn't exist
    int gcd = extendedEuclidean(x, totient, &x1, &y1);

    if(gcd != 1){
        return -1; // Indicate that inverse doesn't exist
    }

    //if y1 is negative, make it positive
    if(x1 < 0){
        x1 = totient + x1;
    }
    
    return x1;
}

int extendedEuclidean(int remainder, int quotient, int* x, int* y){

    /* NOTE
        ax + by = d = gcd(a,b)
        where a = quotient, b = remainder
        => d = quotient*x + remainder*y

        Multiplicative inverse of a mod b is x when d = 1
    */

    // Stop condition
    if(remainder == 0){
        // y = 1, x = 0 at last step when remainder is 0
        *x = 0;
        *y = 1;
        return quotient;
    }

    int x1, y1; // To store results of recursive call
    
    // remainder will be quotient in next call
    int gcd = extendedEuclidean(quotient % remainder, remainder, &x1, &y1);

    /*  Update x and y using results of recursive call
        d = quotient*x1 + remainder*y1
        
        => y = x1
        => x = y1 - (quotient/remainder)*x1
    */
    *x = y1 - (quotient / remainder) * x1;
    *y = x1;

    return gcd;
}