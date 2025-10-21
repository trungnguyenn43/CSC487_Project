#pragma once

//Entries
int DiffHellman_GenPublicKey(int*, int*, int*);
int DiffHellman_GenShareKey(const int , const int, const int );

// Get random prime number
int getRandomPrime();
int modExp(int, int, const int);
int primitiveRoot(int);
int gcd(int, int );