#include "../lib/header/key_handle.h";

unsigned char* GenerateSessionKey(const EVP_MD* hash_type, const EVP_CIPHER* cypher_type, unsigned char* input, size_t input_length, unsigned int* digest_length) {
    unsigned char* full_key = ComputeHash(hash_type, input, input_length, digest_length);
    if (*digest_length > EVP_CIPHER_key_length(cypher_type)) {
        unsigned char* truncated_key = (unsigned char*) malloc(EVP_CIPHER_key_length(cypher_type));
        if (truncated_key != NULL) {
            memcpy(truncated_key, full_key, EVP_CIPHER_key_length(cypher_type));
        }
        free(full_key);
        return truncated_key;
    }
    return full_key;
}

unsigned char* GeneratePreSharedSecret(EVP_PKEY* my_prvkey, EVP_PKEY* peer_pubkey, size_t secret_length) {
    /* Initializing shared secret derivation context */
    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(my_prvkey, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey);
    EVP_PKEY_derive(ctx_drv, NULL, &secret_length);
    unsigned char* secret = (unsigned char*)malloc(secret_length);
    if (secret!=NULL) {
        /* Deriving shared secret */
        EVP_PKEY_derive(ctx_drv, secret, &secret_length);
    }
    EVP_PKEY_CTX_free(ctx_drv);
    return secret;
}