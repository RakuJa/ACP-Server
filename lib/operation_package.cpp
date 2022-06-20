#include "../header/operation_package.h"

// OPERATION PACKAGE CLASS PRIVATE FUNCTIONS

void OperationPackage::setAAD(AAD* givenAad) {
    *aad = *givenAad;
}

/**
 * @brief Deallocates previous iv, allocate new memory for the iv and saves a random there. If it fails return FAIL and deallocates the iv
 * 
 * @return int FAIL if it could not generate random number, otherwise 1
 */
int OperationPackage::generateIv() {
    if (iv != NULL) delete[] iv;
    iv = new unsigned char[IV_LENGTH];
    int randomGenResult = RandomGenerator(iv, IV_LENGTH);
    if (randomGenResult == FAIL) {
        delete[] iv;
        return FAIL;
    }
    return 1;
}

void OperationPackage::setPayload(unsigned char* givenPayload) {
    *payload = *givenPayload;
}

void OperationPackage::setTag(unsigned char* givenTag) {
    *tag = *givenTag;
}

// ==================================================================================================

int OperationPackage::EncryptPlaintextWithGcm(unsigned char* plaintext, int plaintextLength, AAD* givenAad, unsigned char* key) {

    int length = 0;

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();

    if (generateIv() == FAIL || EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv) == FAIL) {
        std::cerr << "Failed to initialize encrypt init context " << std::endl;
        return FAIL;
    }
    unsigned char* charsOfAAD = convertAADtoUnsignedChars(givenAad);
    int updateResult = EVP_EncryptUpdate(ctx, plaintext, &length, charsOfAAD, AAD_LENGTH);
    delete[] charsOfAAD;
    if (updateResult != 1) {
        return NULL;
    }
    if (EVP_EncryptUpdate(ctx, payload, &length, plaintext, plaintextLength) != 1) {
        return NULL;
    }
    
    *payload = length;

    if (EVP_EncryptFinal(ctx, payload + *payload, &length) != 1) {
        return NULL;
    }

    *payload += length;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LENGTH, tag) != 1) {
        return NULL;
    }
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    return 1;


}

//UTILITY
/**
 * @brief Converts AAD struct to unsigned chars allocating memory
 * 
 * @param aad 
 * @return unsigned* concatenation of struct values REMEMBER TO DELETE AFTER USE
 */
unsigned char* convertAADtoUnsignedChars(AAD* aad) {
    // REMEMBER THE AAD IS 4 BYTE OPERATIONID | 8 BYTE MESSAGE COUNTER | 8 BYTE PAYLOADLENGTH | 4 BYTE OPTIONAL VARIABLE
    if (aad == NULL) return NULL;
    unsigned char* returnAAD = new unsigned char[AAD_LENGTH];
    memmove(returnAAD, &(aad->operationId), sizeof(uint32_t));
	memmove(returnAAD + sizeof(uint32_t), &(aad->messageCounter), sizeof(u_int64_t));
    memmove(returnAAD + sizeof(uint32_t) + sizeof(uint64_t), &(aad->payloadLength), sizeof(u_int64_t));
    memmove(returnAAD + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t), &(aad->optionalVariable), sizeof(u_int32_t));
    return returnAAD;
}