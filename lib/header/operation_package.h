#ifndef OPERATION_PACKAGE_H
#define OPERATION_PACKAGE_H

#include <stdint.h>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "utils.h"


typedef struct AAD  {
    uint32_t operationId;
    uint64_t messageCounter;
    uint64_t payloadLength;
    uint32_t optionalVariable;

};

unsigned char* convertAADtoUnsignedChars(AAD* aad);

class OperationPackage {

    private:
        AAD* aad;
        unsigned char* iv;
        unsigned char* payload;
        unsigned char* tag;

        void setAAD(AAD* aad);

        int generateIv();

        void setPayload(unsigned char* givenPayload);

        void setTag(unsigned char* givenTag);

    public:



        int EncryptPlaintextWithGcm(unsigned char* plaintext, int plaintextLength, AAD* givenAad, unsigned char* key);

        int DecryptCyphertextWithGcm(unsigned char* cyphertext, int cyphertextLength, AAD* givenAad, unsigned char* key);


};


#endif