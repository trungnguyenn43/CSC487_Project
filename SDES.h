#pragma once
#include <stdbool.h>

// Entry point for encryption
bool* SDES(const bool[8], const bool[10], bool[8]);

// Entry point for decryption
bool* SDES_decrypt(const bool[8], const bool[10], bool[8]);

char* hex2Bin(const char*);

char binDigits2Hex(const char *);

const char* hexDigitsToBin(const char);

char *bin2Hex(const char *);

void keyGen(const char*);

char* p10_block(const char*);

char* ls_block(char*, const int);

char* p8_block(const char*, const char*);

char* fk_block(const char*, const char*, const char*);

char* ip_block(const char*);

char* ip1_block(const char*);

char* ep_block(const char*);

char* s0_block(const char*);

char* s1_block(const char*);

char* p4_block(const char*);

char XOR(char, char);

