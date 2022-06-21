#include "../lib/header/operation_package.h"

// OPERATION PACKAGE CLASS PRIVATE FUNCTIONS


OperationPackage::AAD::AAD() {
    operationId = new uint32_t[sizeof(uint32_t)];
    messageCounter = new uint64_t[sizeof(uint64_t)];
    payloadLength = new uint64_t[sizeof(uint64_t)];
    optionalVariable = new uint32_t[sizeof(uint32_t)];
}

OperationPackage::AAD::~AAD() {
    delete[] operationId;
    delete[] messageCounter;
    delete[] payloadLength;
    delete[] optionalVariable;
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
    memmove(charAAD, (aad->operationId), sizeof(uint32_t));
	memmove(charAAD + sizeof(uint32_t), (aad->messageCounter), sizeof(u_int64_t));
    memmove(charAAD + sizeof(uint32_t) + sizeof(uint64_t), (aad->payloadLength), sizeof(u_int64_t));
    memmove(charAAD + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(u_int64_t), (aad->optionalVariable), sizeof(u_int32_t));
    return 1;
}

// ==================================================================================================

OperationPackage::OperationPackage() {
    iv = new unsigned char [IV_LENGTH];
    payload = new unsigned char[PAYLOAD_BUFFER_LENGTH];
    tag = new unsigned char[TAG_LENGTH];
    charAAD = new unsigned char[AAD_LENGTH];
    aad = new AAD();
}

OperationPackage::~OperationPackage() {
    delete[] iv;
    delete[] payload;
    delete[] tag;
    delete[] charAAD;
    delete[] aad;
}


int OperationPackage::ResetContext() {
    delete[] iv;
    delete[] payload;
    delete[] tag;
    delete[] charAAD;
    

    iv = new unsigned char [IV_LENGTH];
    payload = new unsigned char[PAYLOAD_BUFFER_LENGTH];
    tag = new unsigned char[TAG_LENGTH];
    charAAD = new unsigned char[AAD_LENGTH];
    aad = new AAD();

    return 1;
}


int OperationPackage::EncryptInit(uint32_t givenOpID, uint64_t msgCounter, uint32_t optVar) {
    *(aad ->operationId) = givenOpID;
    *(aad ->messageCounter) = msgCounter;
    *(aad ->optionalVariable) = optVar;
    return 1;
}


int OperationPackage::EncryptUpdate(unsigned char* plaintext, int plaintextLength, unsigned char* key) {

    int length = 0;


     /* Create and initialise the context */
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        std::cerr << "Failed to initialize context" << std::endl;
    }


     /* Initialise the encryption operation. */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
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


    payload = new unsigned char[16];


    if (EVP_EncryptUpdate(ctx, payload, &length, plaintext, plaintextLength) != 1) {
        std::cout << "Failed to update context 2" <<std::endl;
        return FAIL;
    }
    *(aad->payloadLength) = length;
    if (EVP_EncryptFinal_ex(ctx, payload + *payload, &length) != 1) {
        std::cout << "Failed to finalize context 3" <<std::endl;
        return FAIL;
    }

    *(aad->payloadLength) += length;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LENGTH, tag) != 1) {
        std::cout << "Failed to get tag" <<std::endl;
        return FAIL;
    }
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return 1;

}


unsigned char* OperationPackage::EncryptFinalize(int& length) {
    // AAD | PAYLOAD | TAG | IV
    uint32_t payloadCurrLength = *(aad->payloadLength);


    length = AAD_LENGTH +  payloadCurrLength + TAG_LENGTH + IV_LENGTH;

    std::cout << "TOTAL LENGTH OF MESSAGE" << std::endl;
    unsigned char* toExport = new unsigned char[length];
    UpdateCharAAD();
    memmove(toExport, charAAD, AAD_LENGTH);
    memmove(toExport + AAD_LENGTH, payload, payloadCurrLength);
    memmove(toExport + AAD_LENGTH + payloadCurrLength, tag, TAG_LENGTH);
    memmove(toExport + AAD_LENGTH + payloadCurrLength + TAG_LENGTH, iv, IV_LENGTH);

    std::cout << "=========================" << std::endl;
    std::cout << payload << std::endl;
    std::cout << tag << std::endl;
    std::cout << iv << std::endl;
    std::cout << "=========================" << std::endl;

    std::cout << "======================" << std::endl;
    std::cout << "ENCRYPT AAD " << std::endl;
    std::cout << *(aad -> operationId) << std::endl;
    std::cout << *(aad -> messageCounter) << std::endl;
    std::cout << *(aad -> payloadLength) << std::endl;
    std::cout << *(aad -> optionalVariable) << std::endl;
    std::cout << "======================" << std::endl;

    return toExport;

}

int OperationPackage::DecryptInit(unsigned char* givenAAD) {
    std::cout << "======================" << std::endl;
    std::cout << "Start init decrytp" << std::endl;
    memmove(aad->operationId, givenAAD, sizeof(uint32_t));
    memmove(aad->messageCounter, givenAAD+sizeof(uint32_t), sizeof(uint64_t));
    memmove(aad->payloadLength, givenAAD+sizeof(uint32_t)+ sizeof(uint64_t), sizeof(uint64_t));
    memmove(aad->optionalVariable, givenAAD+sizeof(uint32_t)+ sizeof(uint64_t)+ sizeof(uint64_t), sizeof(uint32_t));

    std::cout << "======================" << std::endl;
    std::cout << "DECRYPT AAD " << std::endl;
    std::cout << *(aad -> operationId) << std::endl;
    std::cout << *(aad -> messageCounter) << std::endl;
    std::cout << *(aad -> payloadLength) << std::endl;
    std::cout << *(aad -> optionalVariable) << std::endl;
    std::cout << "======================" << std::endl;

    return 1;

}

int OperationPackage::DecryptUpdate(unsigned char* givenCyphertext) {
    memmove(payload, givenCyphertext, *(aad->payloadLength));
    memmove(tag, givenCyphertext + *(aad->payloadLength), TAG_LENGTH);
    memmove(iv, givenCyphertext  + *(aad->payloadLength) + TAG_LENGTH, IV_LENGTH);

    return 1;
}


int OperationPackage::DecryptFinalize(unsigned char* plaintext, unsigned char* key) {
    int length = 0;
    int plaintextLength = 0;


    std::cout << "=========================" << std::endl;
    std::cout << payload << std::endl;
    std::cout << tag << std::endl;
    std::cout << iv << std::endl;
    std::cout << "=========================" << std::endl;


     /* Create and initialise the context */
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        std::cerr << "Failed to initialize context" << std::endl;
        return FAIL;
    }

         /* Initialise the encryption operation. */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == FAIL) {
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

    // std::cout << cyphertext << std::endl;

    /* Initialise key and IV */
    if(GenerateIv()==FAIL || EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ) {
        std::cerr << " Failed to set iv and key" << std::endl;
        return FAIL;
    }
    UpdateCharAAD();
    if (EVP_DecryptUpdate(ctx, NULL, &length, charAAD, AAD_LENGTH) != 1) {
        std::cerr << " Failed aad decrypt update " << std::endl;
        return FAIL;
    }

    plaintext = new unsigned char[16];
    if (EVP_DecryptUpdate(ctx, plaintext, &length, payload, *(aad->payloadLength)) != 1) {
        std::cerr << "Error first decrypt update " << std::endl;
        return FAIL;
    }

    plaintextLength = length;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH, tag) != 1) {
        std::cerr << "Failed validating tag" << std::endl;
        return FAIL;
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + length, &length);
    
    EVP_CIPHER_CTX_free(ctx);
    std::cout << ret << std::endl;
    std::cout << plaintext << std::endl;
    if (ret > 0) {
        plaintextLength +=length;
        return plaintextLength;
    } else {
        std::cerr << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return -1;
    }


}


