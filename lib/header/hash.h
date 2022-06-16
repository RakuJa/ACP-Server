#include <openssl/evp.h>

unsigned char* ComputeHash(const EVP_MD*, unsigned char*, size_t, unsigned int*);

unsigned char* ComputeSign(const EVP_MD*, unsigned char*, size_t, unsigned int*,  EVP_PKEY*);

int VerifySign(const EVP_MD*, unsigned char*, size_t, unsigned char*, unsigned int, EVP_PKEY*);