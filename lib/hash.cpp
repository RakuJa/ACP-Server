#include "header/hash.h"

unsigned char* ComputeHash(const EVP_MD* hash_type, unsigned char* input, size_t in_length, unsigned int* digest_length) {
    unsigned char* digest;

    // Buffer allocation for the digest
    digest = (unsigned char*) malloc(EVP_MD_size(hash_type));

    if (digest != NULL) {
        // Context allocation 
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

        EVP_DigestInit(md_ctx, hash_type);
        EVP_DigestUpdate(md_ctx, input, in_length);
        EVP_DigestFinal(md_ctx, digest, digest_length);
        EVP_MD_CTX_free(md_ctx);
    }
    return digest;
}

unsigned char* ComputeSign(const EVP_MD* hash_type, unsigned char* input, size_t in_length, unsigned int* signature_length,  EVP_PKEY* key) {

    unsigned char* signature;

    // Buffer allocation for the signature
    signature = (unsigned char*) malloc(EVP_PKEY_size(key));
    if (signature != NULL) {
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        EVP_SignInit(md_ctx, hash_type);
        EVP_SignUpdate(md_ctx, input, in_length);
        EVP_SignFinal(md_ctx, signature, signature_length, key);
        EVP_MD_CTX_free(md_ctx);
    }
    return signature;
}

int VerifySign(const EVP_MD* hash_type, unsigned char* input, size_t in_length, unsigned char* signature, unsigned int signature_length, EVP_PKEY* key) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(md_ctx,hash_type);
    EVP_VerifyUpdate(md_ctx,input,in_length);
    int result = EVP_VerifyFinal(md_ctx,signature,signature_length,key);
    EVP_MD_CTX_free(md_ctx);
    return result;
}