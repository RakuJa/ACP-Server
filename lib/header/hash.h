#ifndef HASH_H
#define HASH_H

#include <openssl/evp.h>

unsigned char* ComputeHash(const EVP_MD*, unsigned char*, size_t, unsigned int*);

unsigned char* ComputeSign(const EVP_MD*, const unsigned char*, size_t, u_int32_t&,  EVP_PKEY*);

int VerifySign(const EVP_MD*, unsigned char*, size_t, const unsigned char*, unsigned int, EVP_PKEY*);

#endif