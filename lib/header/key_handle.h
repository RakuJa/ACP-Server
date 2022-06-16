#include "hash.h"
#include <string.h>

unsigned char* GenerateSessionKey(const EVP_MD*, const EVP_CIPHER*, unsigned char*, size_t, unsigned int*);

unsigned char* GeneratePreSharedSecret(EVP_PKEY*, EVP_PKEY*, size_t);