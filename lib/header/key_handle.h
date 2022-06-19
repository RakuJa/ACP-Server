#include "hash.h"
#include <string.h>
#include <iostream>

unsigned char* GetDefaultSessionKeyFromPeerPublicAndMyPrivate(EVP_PKEY* myPrivateKey, unsigned char* peerPublicDHKey, uint32_t& peerDhPublicKeyLength);

unsigned char* GenerateSessionKey(const EVP_MD*, const EVP_CIPHER*, unsigned char*, size_t, unsigned int*);

unsigned char* GeneratePreSharedSecret(EVP_PKEY*, EVP_PKEY*, size_t);

EVP_PKEY* ConvertUnsignedCharToPublicDHKey(std::string filename, unsigned char* key, uint32_t& key_length);

EVP_PKEY* GenerateDiffieHellmanPrivateAndPublicPair();
unsigned char* ExtractPublicKey(const char* fileName, EVP_PKEY* myPPKey, u_int32_t& publicKeyLength);
unsigned char* ConvertPublicKeyToCharsBuffer(FILE* publicKeyPEM, uint32_t* resultBufferLength);

EVP_PKEY* ReadRSAPrivateKey(const char*);

std::string FromPublicKeyFileNameToPath(std::string);

EVP_PKEY* ReadRSAPublicKey(const char*);

