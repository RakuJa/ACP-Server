#ifndef OPERATION_PACKAGE_H
#define OPERATION_PACKAGE_H

#include <stdint.h>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include "costants.h"
#include "hash.h"



struct AAD  {
    uint32_t operationId;
    uint64_t messageCounter;
    uint64_t payloadLength;
    uint32_t optionalVariable;

};



class OperationPackage {

    private:
        AAD aad;
        unsigned char* iv;
        unsigned char* payload;
        unsigned char* tag;

        unsigned char* charAAD;

        void setAAD(AAD aad);

        int GenerateIv();

        int UpdateCharAAD();

    public:

        OperationPackage();

        OperationPackage(AAD);

        ~OperationPackage();

        int EncryptPlaintextWithGcm(unsigned char*, int, AAD*, unsigned char*);

        //int DecryptCyphertextWithGcm(unsigned char*, int, AAD*, unsigned char*);

        unsigned char* ExportUnsignedCharsAfterEncryption(int&);


};


#endif