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







class OperationPackage {

    private:

        struct AAD  {
            uint32_t* operationId;
            uint64_t* messageCounter;
            uint64_t* payloadLength;
            uint32_t* optionalVariable;

            AAD();

            ~AAD();

        };

        AAD* aad;
        
        unsigned char* iv;
        unsigned char* payload;
        unsigned char* tag;

        unsigned char* charAAD;

        void setAAD(AAD aad);

        int GenerateIv();

        int UpdateCharAAD();

    public:

        OperationPackage();

        ~OperationPackage();

        int EncryptInit(uint32_t, uint64_t, uint32_t);

        int EncryptUpdate(unsigned char*, int, unsigned char*);

        unsigned char* EncryptFinalize(int&);

        int ResetContext();

        int DecryptInit(unsigned char*);

        int DecryptUpdate(unsigned char*);

        int DecryptFinalize(unsigned char*, unsigned char*);


};


#endif