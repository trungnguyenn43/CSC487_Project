#pragma once

//External global variables
extern char plaintext[9]; // 8-bit binary string + null terminator \0
extern char keytext[13];  // 12-bit key + null terminator. The first 2 bits are ignored

// Entry point
char* SDES(char*, char*);

char* hex2Bin(const char*);

const char* hexDigitsToBin(const char);

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

char OR(char, char);

char XOR(char, char);

