
#include "header/network.h"


/*********************************************************
 *                                                       *
 *  _  _   ___   _____ __   __ ____   ____   _  _        *
 * ) \/ ( ) __( )__ __() (_) (/ __ \ /  _ \ ) |) /       *
 * |  \ | | _)    | |  \  _  /))__(( )  ' / | ( (        *
 * )_()_( )___(   )_(   )/ \( \____/ |_()_\ )_|)_\       *
 *                                                       *
 *                                                       *
 * *******************************************************/



int SendMessage(int socket, const void* msg, uint32_t length) {
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


int SendOperationPackage(int socket, uint32_t opId, uint64_t& messageCounter, uint64_t plaintextLength, uint32_t optVar, unsigned char* plaintext, unsigned char* key){
    
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
	unsigned char* messageReceived = NULL;

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
            progressPercentage = i+1==numberOfDataBlocks ? 100 : ((0.0f+i)/numberOfDataBlocks)*100;
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
    float progressPercentage = 0;
    for(uint32_t i = 0; i < numberOfDataBlocks; i++){
        if(ReadOperationPackage(sd, key, opIdRec, messageCounterRec, msgCounter, ciphertextLengthRec, optVarRec, decryptedTextLength, plaintext) != 1 || opIdRec!=OPERATION_ID_DATA){
            std::cerr<<"Error reading data packet" << std::endl;
            fclose(file);
            remove(fileName.c_str());
            throw std::invalid_argument("Error while reading data. Closing connection ..");
        }
        fwrite(plaintext,1,decryptedTextLength,file);
        if (echoOn > 0) {
            progressPercentage = i+1==numberOfDataBlocks ? 100 : ((0.0f+i)/numberOfDataBlocks)*100;
            std::cout << '\r' << "Download progress at: " << progressPercentage << "                          ";
            std::cout.flush();
        }
        delete [] plaintext;
    }
    fflush(file);
    fclose(file);
    return 1;
}