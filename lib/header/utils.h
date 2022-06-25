#ifndef UTILS_H
#define UTILS_H

#include <sys/socket.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <algorithm>
#include <fstream>
#include <openssl/err.h>
#include <string>
#include <vector>
#include <sstream>
#include "costants.h"
#include "operation_package.h"
#include <stdexcept>
#include <dirent.h>




//CANONIZZAZIONE INPUT (USERNAME, FILEPATH, FILENAME ETC)

/*
Removes all instances of the argument character from the argument string, then returns the modified string
*/
std::string RemoveCharacter(std::string input, char character) {
    input.erase(std::remove(input.begin(), input.end(),character), input.end());
    return input;
}

/*
Checks if the string is less than the maximum and if it does contain only alpha numeric.
Returns -1 if the string is not valid
*/
int ValidateString(std::string stringToAnalyze, int maxStringLength) {
    if (stringToAnalyze.length() <= USERNAME_MAX_LENGTH && !stringToAnalyze.empty()) {
        for (std::string::const_iterator s = stringToAnalyze.begin(); s != stringToAnalyze.end(); ++s)
            if (!isalnum(*s) && *s!='.') return FAIL;
        
        return (stringToAnalyze.at(0) != '.') == 0 ? FAIL : 1;
    }
    return FAIL;
}



std::string ReadFile(const std::string &filename) {
    std::ifstream file(filename);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}


void PrintListOfOperations() {
    std::cout << "========================" << std::endl;
    std::cout << "(0) Help" << std::endl;
    std::cout << "(1) Upload" << std::endl;
    std::cout << "(2) Download" << std::endl;
    std::cout << "(3) Delete" << std::endl;
    std::cout << "(4) List" << std::endl;
    std::cout << "(5) Rename" << std::endl;
    std::cout << "(6) Logout" << std::endl;
    std::cout << "========================" << std::endl;
    std::cout << std::endl << "Insert the corresponding number to execute the desired operation:" << std::endl;
}

void PrettyUpPrintToConsole(std:: string output) {
    std::cout << "========================" << std::endl;
    std::cout << output << std::endl;
    std::cout << "========================" << std::endl;
}


int CheckFileExistance(std::string filename) {
	FILE* fileToCheck = fopen(filename.c_str(), "r");
	if (fileToCheck == NULL) {
		return FAIL;
	}
    fclose(fileToCheck);
    return 1;
}

uint32_t GetFileSize(std::string filename) {
    struct stat stat_buf;
    return (stat(filename.c_str(), &stat_buf) == 0 && stat_buf.st_size < UINT32_MAX) ? stat_buf.st_size : 0;
}



uint32_t GetNumberOfDataBlocks(uint64_t fileSize){
    return fileSize/PAYLOAD_BUFFER_MAX_SIZE + (fileSize % PAYLOAD_BUFFER_MAX_SIZE != 0);
}

int ClearBufferArea(unsigned char* buff, int buffLength) {
    memset(buff, 0, buffLength);
    delete[] buff;
    return 1;
}


std::string GetUserStoragePath(std::string username, const char* inputFilename) {
    username = RemoveCharacter(username, '\0');
    std::string storage = "Storage/";
    std::string completeFilename = inputFilename!=NULL? storage + username + '/' + inputFilename : storage + username + '/';
    return completeFilename;
}


std::vector<std::string> GetFilesInDirectory(DIR* directory) {
    std::vector<std::string> listOfFiles;
    std::string currEntry;
    struct dirent *ent; //THX stackoverflow
    if (directory != NULL) {
        while((ent = readdir(directory))!=NULL) {
            currEntry = ent->d_name;
            if (ValidateString(currEntry, FILENAME_LENGTH) !=FAIL) listOfFiles.push_back(currEntry);
        }
    }
    return listOfFiles;
}

std::string ConcatenateFileNames(std::vector<std::string> fileVector, std::string separator) {
    std::string concatResult;
    //TODO GOD I HATE THIS :PUKE:
    bool first = 1;
    std::string cleanEntry;
    for (const auto & entry: fileVector) {
        cleanEntry = RemoveCharacter(entry, '\0');
        if (ValidateString(cleanEntry, FILENAME_LENGTH) == 1) {
            if (first != 1) {
                concatResult.append(separator);
            }
            first = 0;
            concatResult.append(cleanEntry);
        }
    }
    return concatResult;
}

std::vector<std::string> SplitBufferByCharacter(char* buffer, char splitSeparator) {
    std::stringstream ss(buffer);
    std::string currElement;
    std::vector<std::string> fileList;
    if (buffer!=NULL) {
        while(std::getline(ss, currElement, splitSeparator)) {
            fileList.push_back(currElement);
        }
    }
    return fileList;
}










/*********************************************************
 *                                                       *
 *  _  _   ___   _____ __   __ ____   ____   _  _        *
 * ) \/ ( ) __( )__ __() (_) (/ __ \ /  _ \ ) |) /       *
 * |  \ | | _)    | |  \  _  /))__(( )  ' / | ( (        *
 * )_()_( )___(   )_(   )/ \( \____/ |_()_\ )_|)_\       *
 *                                                       *
 *                                                       *
 * *******************************************************/


/*
Fetches the message to send from the given msg buffer and consumes until the given length, then sends to the given socket.
*/
int SendMessage(int socket, const void* msg, u_int32_t length) {
    u_int32_t result = 0;
    int tmp = 0;
    do {
        tmp = send(socket, msg, length, 0);
        if (tmp==FAIL) {
            return FAIL;
        }
        result += tmp;
    } while (result < length);
    // std::cout<<"Sent " << result << " bytes out of " << length << "\n";
    return result;
}


/*
Reads length bytes from the socket and returns them
*/
template<class T>
int ReadMessage(int socket, u_int64_t length, T** outBuffer) {

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
int SendOperationPackage(int socket, u_int32_t opId, u_int64_t& messageCounter, u_int64_t plaintextLength, u_int32_t optVar, unsigned char* plaintext, unsigned char* key){
    
    unsigned char* aad = new unsigned char[AAD_LENGTH];

    if (EncryptInit(aad, opId, messageCounter, plaintextLength, optVar) != 1) {
        delete [] aad;
    }

	uint64_t ciphertext_len;
	unsigned char* ciphertext = new unsigned char[plaintextLength];
	unsigned char* tag = new unsigned char[TAG_LENGTH];
	unsigned char *iv = new unsigned char[IV_LENGTH];

	if (EncryptUpdate(plaintext, plaintextLength, aad, tag, iv, key, ciphertext, &ciphertext_len) != 1) {
        delete [] aad;
		delete [] ciphertext;
		delete [] tag;
		delete [] iv;
		return FAIL;
	}

    int messageLength = ciphertext_len + AAD_LENGTH + IV_LENGTH + TAG_LENGTH;
	unsigned char* messageToSend = new unsigned char[messageLength];

	int encryptResult = EncryptFinal(messageToSend, aad, ciphertext, ciphertext_len, tag, iv);

    delete [] aad;
	delete [] ciphertext;
	delete [] tag;
	delete [] iv;
    if (encryptResult != 1) {
        delete [] messageToSend;
        return FAIL;
    }
    int resultSend = SendMessage(socket, messageToSend, messageLength);
    ++messageCounter;
    delete [] messageToSend;
    if (resultSend == FAIL) {
        throw std::invalid_argument("Connection failed" );
    }
    
    return 1;
}
    

int SendStatusPackage(int sd, unsigned char* key, uint32_t opId, uint64_t& messageCounter) {

    // PREPARE AND SEND ASK FOR UPLOAD
	std::string padding = "0";
	unsigned char *plaintext = (unsigned char *)padding.c_str();
	uint64_t payloadLength = strlen((char*) plaintext); // length = plaintext +1, in questo caso c'è il char di terminazione quindi plaintext
	// Perchè? Perchè - inserisci spiegazione dei blocchi -
    int sendResult = SendOperationPackage(sd, opId, messageCounter, payloadLength, 0, plaintext, key);
    if (sendResult != 1) {
        throw std::invalid_argument("Error sending status package (ABORT/DONE/ACK..), connection cannot be considered stable");
    }
    return sendResult;

}



int ReadOperationPackage(int sd, unsigned char* key, uint32_t& opIdRec, uint64_t& messageCounterRec, uint64_t& expectedCounter, uint64_t& ciphertextLengthRec, uint32_t& optVarRec, uint64_t& decryptedTextLength, unsigned char*& decryptedPayload) {
    
	decryptedTextLength = 0;

	opIdRec = 0;
	messageCounterRec = 0;
	ciphertextLengthRec = 0;
	optVarRec = 0;
    
    unsigned char* aad = NULL;

    if (ReadMessage(sd, AAD_LENGTH, &aad) != 1) {
        std::cerr << "Error reading AAD" << std::endl;
        throw std::invalid_argument("Network error");
    }

	if (DecryptInit(aad, opIdRec, messageCounterRec, ciphertextLengthRec, optVarRec) != 1) {
        std::cerr << "Failed decrypt init with received aad" << std::endl;
        delete [] aad;
        return FAIL;
    }
    if (messageCounterRec != expectedCounter) {
        std::cerr << "Counter out of sync, abort connection..." << std::endl;
        delete [] aad;
        throw std::invalid_argument("Counter out of sync");
    }
    expectedCounter = expectedCounter +1;
    
    int messageLength = ciphertextLengthRec + IV_LENGTH + TAG_LENGTH;
	unsigned char* messageReceived = new unsigned char[messageLength];

    if (ReadMessage(sd, messageLength, &messageReceived) != 1) {
        std::cerr << "Failed read of ciphertext + tag + iv" << std::endl;
        delete [] aad;
        delete [] messageReceived;
        return FAIL;
    }

    unsigned char* tmp = new unsigned char[AAD_LENGTH + messageLength];
    memmove(tmp, aad, AAD_LENGTH);
    memmove(tmp + AAD_LENGTH, messageReceived, messageLength);

    delete[] tmp;

	

	unsigned char* gotCiphertext = new unsigned char[ciphertextLengthRec];
	unsigned char* gotTag = new unsigned char[TAG_LENGTH];
	unsigned char* gotIv = new unsigned char[IV_LENGTH];

	if (DecryptUpdate(messageReceived, gotCiphertext, ciphertextLengthRec, gotTag, gotIv) != 1) {
        std::cerr << "Failed decrypt update" << std::endl;
        delete [] aad;
        delete [] messageReceived;
        delete [] gotCiphertext;
        delete [] gotTag;
        delete [] gotIv;
        return FAIL;
    }

    decryptedPayload = new unsigned char[ciphertextLengthRec+1];
	int resultOfOp = DecryptFinal(gotCiphertext, ciphertextLengthRec, aad, gotTag, gotIv, key, decryptedPayload, &decryptedTextLength);
    if (resultOfOp == FAIL) {
        std::cerr << "Failed to finalize decrypt" << std::endl;
        delete[] decryptedPayload;
        return resultOfOp;
    }
    delete [] aad;
    delete [] messageReceived;
    delete [] gotCiphertext;
    delete [] gotTag;
    delete [] gotIv;

    return resultOfOp;

}


int SendFileInOperationPackage(int sd, std::string fileName, uint32_t numberOfDataBlocks, uint64_t fileLength, unsigned char* key, uint64_t& msgCounter, int echoOn) {
    
    FILE* file = fopen(fileName.c_str(), "r");
    
    if(!file) {
        std::cerr<<"Error opening file in read mode" << std::endl;
        return false;
    }
    unsigned char* data;
    uint32_t currDataBlockFileLength;
    float progressPercentage = 0;
    for(uint32_t i = 0; i < numberOfDataBlocks; i++){
        if(numberOfDataBlocks == 1){
            currDataBlockFileLength = fileLength;
        }
        else if(numberOfDataBlocks - 1 == i){
            currDataBlockFileLength = fileLength%PAYLOAD_BUFFER_MAX_SIZE;
        }
        else{
            currDataBlockFileLength = PAYLOAD_BUFFER_MAX_SIZE;
        }
        data = new unsigned char[currDataBlockFileLength];
        fread(data,1,currDataBlockFileLength,file);
        if (SendOperationPackage(sd, OPERATION_ID_DATA, msgCounter, currDataBlockFileLength, 0, data, key) != 1) {
            delete[] data;
            return FAIL;
        }
        if (echoOn > 0) {
            progressPercentage = ((0.0f+i)/numberOfDataBlocks)*100;
            std::cout << '\r' << "Upload progress at: " << progressPercentage << "                          ";
            std::cout.flush();
        }

        delete[] data;
    }
    std::cout << std::endl;
    fclose(file);
    return 1;
}


int ReadFileInOperationPackage(int sd, std::string fileName, uint32_t numberOfDataBlocks, unsigned char* key, uint64_t& msgCounter, int echoOn) {


	uint64_t decryptedTextLength = 0;

	uint32_t opIdRec = 0;
	uint64_t messageCounterRec = 0;
	uint64_t ciphertextLengthRec = 0;
	uint32_t optVarRec = 0;

    FILE* file = fopen(fileName.c_str(),"w+");
    if(!file) {
        std::cerr<<"Errore nell'apertura del file in scrittura\n";
        throw std::invalid_argument("Error with filesystem, internal error? Closing connection ..");
    }
    unsigned char* plaintext = NULL;
    for(uint32_t i = 0; i < numberOfDataBlocks; i++){
        if(ReadOperationPackage(sd, key, opIdRec, messageCounterRec, msgCounter, ciphertextLengthRec, optVarRec, decryptedTextLength, plaintext) != 1){
            std::cerr<<"Error reading data packet" << std::endl;
            fclose(file);
            remove(fileName.c_str());
            throw std::invalid_argument("Error with filesystem, internal error? Closing connection ..");
        }
        fwrite(plaintext,1,decryptedTextLength,file);
        if (echoOn > 0) {
            float progressPercentage = ((0.0f+i)/numberOfDataBlocks)*100;
            std::cout << '\r' << "Download progress at: " << progressPercentage << "                          ";
            std::cout.flush();
        }
        delete [] plaintext;
    }
    fflush(file);
    fclose(file);
    return 1;
}
#endif