#pragma once
#include <stdlib.h>
#include <string.h>
#include <time.h>

const int VALID_DURATION_SECONDS = 24 * 60 * 60; // 1 day

struct crlEntry {
    char serialNumber[256];
    time_t revocationDate;
};

struct crlInfo {
    char crlFileName[256];
    char algorithm[50];
    char parameters[100];
    char issuerName[100];
    time_t thisUpdate = time(NULL);
    time_t nextUpdate = thisUpdate + 24 * 60 * 60;
    int numEntries = 0;
    unsigned int privateKey;
    unsigned int publicKey;
    unsigned int n;
};

void certGen(unsigned int , unsigned int, unsigned int );

int certVerify(const crlEntry [], int);

void signFile(char [], unsigned int , unsigned int , unsigned int );

int verifyFileSignature(char []);

int loadCRLEntry(crlInfo*, crlEntry [], unsigned int , unsigned int , unsigned int );

void saveCRL(crlInfo* ,crlEntry [], unsigned int , unsigned int , unsigned int );

void addCRLEntry(crlEntry [], int *);

void rmCRLEntry(crlEntry [], int *, const char []);

crlInfo newCRLFile(char [], unsigned int , unsigned int , unsigned int );
