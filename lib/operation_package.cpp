#include "../lib/header/operation_package.h"

// OPERATION PACKAGE CLASS PRIVATE FUNCTIONS



void OperationPackage::setAAD(AAD givenAad) {
    aad = givenAad;
}

int OperationPackage::GenerateIv() {
    return RandomGenerator(iv, IV_LENGTH);
}

//UTILITY
/**
 * @brief Converts AAD struct to unsigned chars allocating memory
 * 
 * @param aad 
 * @return unsigned* concatenation of struct values REMEMBER TO DELETE AFTER USE
 */
int OperationPackage::UpdateCharAAD() {
    // REMEMBER THE AAD IS 4 BYTE OPERATIONID | 8 BYTE MESSAGE COUNTER | 8 BYTE PAYLOADLENGTH | 4 BYTE OPTIONAL VARIABLE
    std::cout << "Initializing export AAD" << std::endl;
    memmove(charAAD, &(aad.operationId), sizeof(uint32_t));
	memmove(charAAD + sizeof(uint32_t), &(aad.messageCounter), sizeof(u_int64_t));
    memmove(charAAD + sizeof(uint32_t) + sizeof(uint64_t), &(aad.payloadLength), sizeof(u_int64_t));
    memmove(charAAD + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t), &(aad.optionalVariable), sizeof(u_int32_t));
    std::cout << "Ending export AAD " << std::endl;
    return 1;
}

// ==================================================================================================

OperationPackage::OperationPackage() {
    iv = new unsigned char [IV_LENGTH];
    payload = new unsigned char[PAYLOAD_BUFFER_LENGTH];
    tag = new unsigned char[TAG_LENGTH];
    charAAD = new unsigned char[AAD_LENGTH];
}

OperationPackage::OperationPackage(AAD givenAAD) {
    aad = givenAAD;
}

OperationPackage::~OperationPackage() {
    delete[] iv;
    delete[] payload;
    delete[] tag;
    delete[] charAAD;
}


int OperationPackage::EncryptPlaintextWithGcm(unsigned char* plaintext, int plaintextLength, AAD* givenAad, unsigned char* key) {

    int length = 0;


     /* Create and initialise the context */
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        std::cerr << "Failed to initialize context" << std::endl;
    }


     /* Initialise the encryption operation. */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == FAIL) {
        std::cerr << "Failed to initialize context" << std::endl;
        return FAIL;
    }

      /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, NULL)) {
        std::cerr << "Failed to initialize context with iv" << std::endl;
        return FAIL;
    }

    /* Initialise key and IV */
    if(GenerateIv()==FAIL || EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ) {
        std::cerr << " Failed to set iv and key" << std::endl;
        return FAIL;
    }

    UpdateCharAAD();
    int updateResult = EVP_EncryptUpdate(ctx, NULL, &length, charAAD, AAD_LENGTH);
    
    if (updateResult != 1) {
        std::cout << "Failed to update context with aad" <<std::endl;
        return FAIL;
    }

    int len = 0;

    payload = new unsigned char[2048];

    if (EVP_EncryptUpdate(ctx, payload, &length, plaintext, plaintextLength) != 1) {
        std::cout << "Failed to update context 2" <<std::endl;
        return FAIL;
    }
    aad.payloadLength = length;
    std::cout << 5 << std::endl;
    if (EVP_EncryptFinal_ex(ctx, payload + *payload, &length) != 1) {
        std::cout << "Failed to finalize context 3" <<std::endl;
        return FAIL;
    }

    aad.payloadLength += length;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LENGTH, tag) != 1) {
        std::cout << "Failed to get tag" <<std::endl;
        return FAIL;
    }
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return 1;

}

unsigned char* OperationPackage::ExportUnsignedCharsAfterEncryption(int& length) {
    std::cout << "Exporting ... " << std::endl;
    // AAD | PAYLOAD | TAG | IV
    length = AAD_LENGTH +  aad.payloadLength + TAG_LENGTH + IV_LENGTH;
    unsigned char* toExport = new unsigned char[length];
    UpdateCharAAD();
    memmove(toExport, charAAD, AAD_LENGTH);
    memmove(toExport + AAD_LENGTH, payload, aad.payloadLength);
    memmove(toExport + AAD_LENGTH + aad.payloadLength, tag, TAG_LENGTH);
    memmove(toExport + AAD_LENGTH + aad.payloadLength + IV_LENGTH, iv, IV_LENGTH);
    std::cout << "Finished Exporting ... " << std::endl;
    return toExport;

}