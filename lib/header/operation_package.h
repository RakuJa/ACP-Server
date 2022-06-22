#ifndef OPERATION_PACKAGE_H
#define OPERATION_PACKAGE_H

#include <stdint.h>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include "costants.h"
#include "hash.h"

int EncryptUpdate(unsigned char *plaintext, int plaintextLength,
                unsigned char *aad,
                unsigned char *tag,
                unsigned char *iv,
                unsigned char *key,
                unsigned char *ciphertext,
                uint64_t* ciphertextLength);


int DecryptFinal(unsigned char *ciphertext, uint64_t ciphertextLength,
                unsigned char *aad,
                unsigned char *tag,
                unsigned char *iv,
                unsigned char *key,
                unsigned char *plaintext,
                uint64_t* plaintextLength);


int EncryptInit(unsigned char*& aad, uint32_t opId, uint64_t messageCounter, uint64_t payloadLength, uint32_t optVar);
int EncryptFinal(unsigned char*& messageToSend, unsigned char* aad, unsigned char* ciphertext, uint32_t ciphertextLength, unsigned char* tag, unsigned char* iv);


int DecryptInit(unsigned char* aad, uint32_t& opId, uint64_t& messageCounter, uint64_t& payloadLength, uint32_t& optVar);
int DecryptUpdate(unsigned char* msg, unsigned char*& ciphertext, u_int64_t ciphertextLength, unsigned char*& tag, unsigned char*& iv);

void HandleErrors(void);
#endif