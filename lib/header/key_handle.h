#include "hash.h"
#include <string.h>
#include <iostream>



unsigned char* GenerateSessionKey(const EVP_MD*, const EVP_CIPHER*, unsigned char*, size_t, unsigned int*);

unsigned char* GeneratePreSharedSecret(EVP_PKEY*, EVP_PKEY*, size_t);

EVP_PKEY* GenerateDiffieHellmanPrivateAndPublicPair();
unsigned char* ExtractPublicKey(const char* fileName, EVP_PKEY* myPPKey, EVP_PKEY* publicKey, u_int32_t& publicKeyLength);
unsigned char* ConvertPublicKeyToCharsBuffer(FILE* publicKeyPEM, uint32_t* resultBufferLength);

EVP_PKEY* ReadRSAPrivateKey(const char*);