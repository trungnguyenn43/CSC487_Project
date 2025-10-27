
#pragma once

// Project 2C
unsigned int RSA_KeyGen(unsigned int , unsigned int , unsigned int* );
unsigned int totientMultiplcativeInverse(unsigned int , unsigned int, unsigned int* );
unsigned int selectE_RSA(unsigned int);
unsigned int selectE_2Primes(unsigned int, unsigned int );

unsigned int multiplicativeInverse(unsigned int , unsigned int );
unsigned int extendedEuclidean(unsigned int , unsigned int , int* ,  int* );

unsigned int gcd(unsigned int , unsigned int );

// Project 2B
void CBCHash(const char* , const char [2], char [3] , char [2]);
int hexCharToInt(char); 
char hexIntToChar(int );