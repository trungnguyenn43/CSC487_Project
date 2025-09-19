#pragma once

// Entry point
char* SDES(char*, char*);

char* hex2Bin(const char*);

char* hexDigitsToBin(const char);

void keyGen(char*);

char* p10_block(char*);

char* ls_block(char*, const int);

char* p8_block(char*, char*);

char* ip_block(char*);

char* ip1_block(char*);

char* ep_block(char*);

char* s1_block(char*);

char* s2_block(char*);

char* p4_block(char*);

