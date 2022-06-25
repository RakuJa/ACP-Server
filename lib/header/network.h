#ifndef NETWORK_H
#define NETWORK_H


#include "costants.h"
#include "operation_package.h"

#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <stdexcept>





/*********************************************************
 *                                                       *
 *  _  _   ___   _____ __   __ ____   ____   _  _        *
 * ) \/ ( ) __( )__ __() (_) (/ __ \ /  _ \ ) |) /       *
 * |  \ | | _)    | |  \  _  /))__(( )  ' / | ( (        *
 * )_()_( )___(   )_(   )/ \( \____/ |_()_\ )_|)_\       *
 *                                                       *
 *                                                       *
 * *******************************************************/


/**
 * @brief Writes to socket length bytes from given buffer
 * 
 * @param socket writes to
 * @param msg reads from
 * @param length amount of bytes to read and write
 * @return int 
 */
int SendMessage(int socket, const void* msg, uint32_t length);

/**
 * @brief Reads from socket length bytes to given buffer
 * 
 * @tparam T template
 * @param socket reads from
 * @param length amount of bytes to read
 * @param outBuffer buffer to write to
 * @return int success of the operation, -1 if FAILED
 */
template<class T>
int ReadMessage(int socket, uint64_t length, T** outBuffer) {

    // READ CONTENT FROM SOCKET

    // u_int64_t result = 0;
    T* msg = new T[length];
    T* tempPointer = msg;

    int tmp = 0;
    do {
        tmp = recv(socket, tempPointer, length, 0);
        if (tmp == FAIL) {
            delete[] msg;
            return FAIL;
        }
        length -=tmp;
        tempPointer +=tmp;
        tmp = 0;
    } while (length > 0);
    // std::cout <<"Received " << result << " bytes out of " << length << "\n";
    *outBuffer = msg;
    return 1;
    
}

/**
 * @brief Encrypts given plaintext with given key, authenticates aad(opId | msgCounter | payloadLength | optVar) and sends message to socket.
 * Increments messageCounter value
 * 
 * @param socket Socket to send the OperationPackage to
 * @param opId creates and authenticates aad with this value inside 
 * @param messageCounter creates and authenticates aad with this value inside 
 * @param plaintextLength creates and authenticates aad with this value inside (also used to allocate memory, so be VERY carefull)
 * @param optVar creates and authenticates aad with this value inside 
 * @param plaintext encrypt this
 * @param key used to encrypt plaintext
 * @return int FAIL if something went wrong encrypting or sending the message
 */
int SendOperationPackage(int socket, uint32_t opId, uint64_t& messageCounter, uint64_t plaintextLength, uint32_t optVar, unsigned char* plaintext, unsigned char* key);
    
/**
 * @brief Prepares an OperationPackage encrypting with padding as payload and optVar, used for ACK, ABORT, DONE etc
 * 
 * @param sd socket
 * @param key used to encrypt
 * @param opId 
 * @param messageCounter 
 * @return int 
 */
int SendStatusPackage(int sd, unsigned char* key, uint32_t opId, uint64_t& messageCounter);

/**
 * @brief Reads an OperationPackage, decrypting it and saving the content to the variables passed as argument.
 * Checks if messageCounterRec is aligned with expected counter and after that it increments expectedCounter
 * 
 * @param sd socket
 * @param key used to decrypt
 * @param opIdRec operation id received
 * @param messageCounterRec counter that has been received, will be compared with expected counter
 * @param expectedCounter counter that will be incremented
 * @param ciphertextLengthRec used internally to check integrity
 * @param optVarRec optional variable received
 * @param decryptedTextLength how many bytes did the received payload contain
 * @param decryptedPayload allocates new memory for this, REMEMBER TO DELETE
 * @return int 
 */
int ReadOperationPackage(int sd, unsigned char* key, uint32_t& opIdRec, uint64_t& messageCounterRec, uint64_t& expectedCounter, uint64_t& ciphertextLengthRec, uint32_t& optVarRec, uint64_t& decryptedTextLength, unsigned char*& decryptedPayload);

/**
 * @brief Utility method used to read from disk and send a file to socket
 * 
 * @param sd socket
 * @param fileName complete (relative or absolute) filename to load the file from
 * @param numberOfDataBlocks number of OperationPackage to send, each OperationPackage will contain a part of the file
 * @param fileLength 
 * @param key used to encrypt
 * @param msgCounter 
 * @param echoOn if this is equal to 1 it will print to console a progress bar (how many OperationPackage have been sent)
 * @return int 
 */
int SendFileInOperationPackage(int sd, std::string fileName, uint32_t numberOfDataBlocks, uint64_t fileLength, unsigned char* key, uint64_t& msgCounter, int echoOn);

/**
 * @brief Utility method used to read from socket and write the content to disk
 * 
 * @param sd 
 * @param fileName 
 * @param numberOfDataBlocks 
 * @param key 
 * @param msgCounter 
 * @param echoOn 
 * @return int 
 */
int ReadFileInOperationPackage(int sd, std::string fileName, uint32_t numberOfDataBlocks, unsigned char* key, uint64_t& msgCounter, int echoOn);

#endif