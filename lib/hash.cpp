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

unsigned char* ComputeSign(const EVP_MD* hash_type, const unsigned char* input, size_t in_length, u_int32_t& signature_length,  EVP_PKEY* key) {

    unsigned char* signature;

    // Buffer allocation for the signature
    signature = (unsigned char*) malloc(EVP_PKEY_size(key));
    if (signature != NULL) {
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        EVP_SignInit(md_ctx, hash_type);
        EVP_SignUpdate(md_ctx, input, in_length);
        EVP_SignFinal(md_ctx, signature, &signature_length, key);
        EVP_MD_CTX_free(md_ctx);
    }
    return signature;
}

/**
 * @brief Verifies given signedMsg with the msgToSign
 * 
 * @param hashType Algorithm used to hash the clear message and compare with signedMsg
 * @param signedMsg signed message to validate
 * @param signedMsgLength message to validate length
 * @param clearMsg clear message to sign and compare
 * @param clearMsgLength clear message length
 * @param key key used to sign the clear message
 * @return int 0 if the signature is invalid, -1 for generic errors and 1 for success
 */
int VerifySign(const EVP_MD* hashType, unsigned char* signedMsg, size_t signedMsgLength, const unsigned char* clearMsg, unsigned int clearMsgLength, EVP_PKEY* key) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(md_ctx,hashType);
    EVP_VerifyUpdate(md_ctx,clearMsg,clearMsgLength);
    int result = EVP_VerifyFinal(md_ctx,signedMsg,signedMsgLength,key);
    EVP_MD_CTX_free(md_ctx);
    return result;
}