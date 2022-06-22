#include "../lib/header/operation_package.h"

void HandleErrors(std::string errorMessage) {
    std::cout << errorMessage << std::endl;
    std::cout<<ERR_error_string(ERR_get_error(),NULL) << std::endl;
    ERR_print_errors_fp(stderr);
    // abort();
}



int EncryptUpdate(unsigned char *plaintext, int plaintextLength,
                unsigned char *aad,
                unsigned char *tag,
                unsigned char *iv,
                unsigned char *key,
                unsigned char *ciphertext,
                uint64_t* ciphertextLength)
{
    EVP_CIPHER_CTX *ctx;
    int len=0;
    *ciphertextLength=0;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        HandleErrors("Error while initializing encrypt context");
        return FAIL;
    }

    if(RandomGenerator(iv, IV_LENGTH) == FAIL ||  EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv) != 1) {
        HandleErrors("Error while setting up encrypt key and iv in encrypt context");
        return FAIL;
    }

    
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, AAD_LENGTH)) {
        HandleErrors("Error while setting up aad in encrypt context");
        return FAIL;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintextLength)) {
        HandleErrors("Error while setting up ciphertext in encrypt context");
        return FAIL;
    }
    *ciphertextLength = len;

    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len)) {
        HandleErrors("Error while encrypting plaintext in encrypt context");
        return FAIL;
    }
    *ciphertextLength += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) {
        HandleErrors("Error while creating tag for encrypted payload and aad in encrypt context");
        return FAIL;
    }

    EVP_CIPHER_CTX_cleanup(ctx);

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}



int DecryptFinal(unsigned char *ciphertext, uint64_t ciphertextLength,
                unsigned char *aad,
                unsigned char *tag,
                unsigned char *iv,
                unsigned char *key,
                unsigned char *plaintext,
                uint64_t* plaintextLength)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ret;

    if(!(ctx = EVP_CIPHER_CTX_new())){
        HandleErrors("Error while initializing decrypt context");
        return FAIL;
    }
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv)){
        HandleErrors("Error while setting up encrypt key and iv in decrypt context");
        return FAIL;
    }

    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, AAD_LENGTH)){
        HandleErrors("Error while setting up aad in decrypt context");
        return FAIL;
    }

    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertextLength)){
        HandleErrors("Error while decrypting ciphertext in decrypt context");
        return FAIL;
    }
    *plaintextLength = len;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)){
        HandleErrors("Error while validating tag in decrypt context");
        return FAIL;
    }

    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_cleanup(ctx);

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        *plaintextLength += len;
        return 1;
    } else {
        HandleErrors("Failed to finalize decrypt, possible causes: wrong pad or invalid aad and tag");
        perror("Decrypt error");
        return FAIL;
    }
}

int EncryptInit(unsigned char*& aad, uint32_t opId, uint64_t messageCounter, uint64_t payloadLength, uint32_t optVar) {
    memmove(aad, &opId, sizeof(uint32_t));
	memmove(aad + sizeof(uint32_t), &messageCounter, sizeof(u_int64_t));
    memmove(aad + sizeof(uint32_t) + sizeof(uint64_t), &payloadLength, sizeof(u_int64_t));
    memmove(aad + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(u_int64_t), &optVar, sizeof(u_int32_t));
    return 1;
}

int EncryptFinal(unsigned char*& messageToSend, unsigned char* aad, unsigned char* ciphertext, uint32_t ciphertextLength, unsigned char* tag, unsigned char* iv) {
    memmove(messageToSend, aad, AAD_LENGTH);
    memmove(messageToSend + AAD_LENGTH, ciphertext, ciphertextLength);
    memmove(messageToSend + AAD_LENGTH + ciphertextLength, tag, TAG_LENGTH);
    memmove(messageToSend + AAD_LENGTH + ciphertextLength + TAG_LENGTH, iv, IV_LENGTH);
        std::cout << "=======================" << std::endl;
    std::cout << "CIPHERTEXT" << std::endl;
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertextLength);
    std::cout << "=======================" << std::endl;
    std::cout << "=======================" << std::endl;
    std::cout << "TAG" << std::endl;
    BIO_dump_fp (stdout, (const char *)tag, TAG_LENGTH);
    std::cout << "=======================" << std::endl;
    std::cout << "=======================" << std::endl;
    std::cout << "IV" << std::endl;
    BIO_dump_fp (stdout, (const char *)iv, IV_LENGTH);
    std::cout << "=======================" << std::endl;
    return 1;
}

int DecryptUpdate(unsigned char* msg, unsigned char*& ciphertext, u_int64_t ciphertextLength, unsigned char*& tag, unsigned char*& iv) {
	memmove(ciphertext, msg, ciphertextLength);
	memmove(tag, msg + ciphertextLength, TAG_LENGTH);
	memmove(iv, msg + ciphertextLength + TAG_LENGTH, IV_LENGTH);

    std::cout << "=======================" << std::endl;
    std::cout << "CIPHERTEXT" << std::endl;
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertextLength);
    std::cout << "=======================" << std::endl;
    std::cout << "=======================" << std::endl;
    std::cout << "TAG" << std::endl;
    BIO_dump_fp (stdout, (const char *)tag, TAG_LENGTH);
    std::cout << "=======================" << std::endl;
    std::cout << "=======================" << std::endl;
    std::cout << "IV" << std::endl;
    BIO_dump_fp (stdout, (const char *)iv, IV_LENGTH);
    std::cout << "=======================" << std::endl;
    return 1;
}

int DecryptInit(unsigned char* aad, uint32_t& opId, uint64_t& messageCounter, uint64_t& payloadLength, uint32_t& optVar) {
    memmove(&opId, aad, sizeof(uint32_t));
    memmove(&messageCounter, aad + sizeof(uint32_t), sizeof(uint64_t));
    memmove(&payloadLength, aad + sizeof(uint32_t) + sizeof(uint64_t), sizeof(uint64_t));
    memmove(&optVar, aad + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint64_t), sizeof(uint32_t));
    return 1;
}