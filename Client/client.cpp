// Daniele Giachetto - Foundation of Cybersecurity Project



#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../lib/header/utils.h"
#include "../lib/header/hash.h"
#include "../lib/header/certificate.h"
#include "../lib/header/key_handle.h"
#include "../lib/header/operation_package.h"


/**
 * @brief Sends the login message to the server, returns NULL if nonce failed to generate or username was refused by the server
 * 
 * @param usernamename will be used to return the username that succeded login
 * @return unsigned* the generated nonce sent to the server or NULL if something went wrong
 */
unsigned char* FirstHandShakeMessageHandler(int sd, std::string & username) {
	
	//                FIRST MESSAGE                //
	/************************************************
	**GENERATE NONCE, GET USERNAME & SEND THEM BOTH**
	*************************************************/

	// Get username
	do {
		printf("Please insert a valid username (only alphanumeric character and length < %d : \n", USERNAME_MAX_LENGTH);
		std::cin>>username;
	} while (std::cin.fail() || ValidateString(username, USERNAME_MAX_LENGTH) == FAIL);

	username.resize(USERNAME_MAX_LENGTH); // add padding to standardize username length and avoid sending a message with username size


	unsigned char* nonceC = new unsigned char[NONCE_LEN];
	// Send first packet, nonce(c) and username
	if (SendMessage(sd, username.c_str(), USERNAME_MAX_LENGTH) == FAIL || RandomGenerator(nonceC, NONCE_LEN) == FAIL || SendMessage(sd, nonceC, NONCE_LEN) == FAIL) {
		std::cerr<<"Error sending username or generating and sending nonce(c)" << std::endl;
		delete[] nonceC;
		return NULL;
	}

	unsigned char* resultOfLogin = NULL;
	if (ReadMessage(sd, sizeof(HANDSHAKE_ERROR), &resultOfLogin) == FAIL || *resultOfLogin == *HANDSHAKE_ERROR) {
		std::cerr << "Username was not valid for the server" << std::endl;
		delete[] nonceC;
		if (resultOfLogin != NULL) delete[] resultOfLogin;
		return NULL;
	}

	delete[] resultOfLogin;
	std::cout << "Username " << username << " is valid, login success!" << std::endl;
	return nonceC;
}

/**
 * @brief Receives the login response from the server, that contains server certificate, nonce(s), sign(nonce(c), A), A(peer public key)
 * in case of error somewhere down the line returns NULL and handles all the frees (except the passed arguments) inside the method
 * 
 * @param sd socket to receive and send messages from
 * @param serverDhPublicKey will be used to return the publicDHKey also called peerDHKey
 * @param nonceC nonce sent previously to the server, used in the method to verify sign(nonce(c), A)
 * @return unsigned* the nonce sent by the server
 */
unsigned char* SecondHandShakeMessageHandler(int sd, unsigned char** serverDhPublicKey, u_int32_t& serverDhPublicKeyLength, unsigned char* nonceC) {
	//                 SECOND MESSAGE                 //
	/***************************************************
	**GETS CERTIFICATE, A, NONCE(S), SIGN(NONCE(C), A)**
	***************************************************/

	/*
	* 1) GETS CERTIFICATE SIZE & CERTIFICATE
	* 2) PARSE AND VALIDATE CERTIFICATE
	* 3) GETS A
	* 4) GETS SIGN(NONCE(C), A)
	*/

	// GETS CERTIFICATE SIZE
	u_int32_t* certificateLength = NULL;
	if (ReadMessage(sd, sizeof(u_int32_t), &certificateLength) == FAIL) {
		std::cerr << "Certificate length received is invalid" << std::endl;
		return NULL;
	}

	// GETS CERTIFICATE
	unsigned char* serverCertificate = NULL;
	if (ReadMessage(sd, *certificateLength, &serverCertificate) == FAIL) {
		std::cerr << "Certificate read failed" << std::endl;
		return NULL;
	}

	// PARSE AND VALIDATE CERTIFICATE
	X509* parsedServerCertificate = ReadCertificate(SERVER_CERT_NAME, serverCertificate, *certificateLength);
	delete[] certificateLength;
	delete[] serverCertificate;
	if (parsedServerCertificate == NULL) {
		std::cerr << "Error parsing server certificate" << std::endl;
		return NULL;
	}
	X509_STORE* store = BuildStore("ClientCrl.pem", "CA.pem");
	if (store == NULL) {
		std::cerr << "Error building certificate store" << std::endl;
		X509_free(parsedServerCertificate);
		return NULL;
	}
	EVP_PKEY* serverRSAPubKey = ValidateCertificate(store, parsedServerCertificate);

	// Not used anymore after validate
	X509_free(parsedServerCertificate);
	X509_STORE_free(store);

	if (serverRSAPubKey == NULL) {
		std::cerr << "Server certificate is not valid" << std::endl;
		SendMessage(sd, HANDSHAKE_ERROR, sizeof(HANDSHAKE_ERROR));
		return NULL;
	}
	SendMessage(sd, HANDSHAKE_ACK, sizeof(HANDSHAKE_ACK));

	// GET A (serverPublicDhKey) LENGTH


	u_int32_t* tmpLength = NULL;	
	if (ReadMessage(sd, sizeof(u_int32_t), &tmpLength) == FAIL) {
		std::cerr << "DiffieHellman public key length received is invalid" << std::endl;
		return NULL;
	}
	serverDhPublicKeyLength = *tmpLength;

	// GET A (serverPublicDhKey)
	if (ReadMessage(sd, serverDhPublicKeyLength, serverDhPublicKey) == FAIL) {
		std::cerr << "Failure while receiving DiffieHellman public key" << std::endl;
		return NULL;
	}

	// READ SIGNATURE

	u_int32_t* serverSignLength = NULL;	
	if (ReadMessage(sd, sizeof(u_int32_t), &serverSignLength) == FAIL) {
		std::cerr << "Server signature length received is invalid" << std::endl;
		return NULL;
	}

	unsigned char* serverSign = NULL;

	if (ReadMessage(sd, *serverSignLength, &serverSign) == FAIL) {
		std::cerr << "Failure while receiving signature" << std::endl;
		return NULL;
	}


	// Sign (NONCE(C) + A)
	
	int msgToSignLength = NONCE_LEN + serverDhPublicKeyLength;
	unsigned char* msgToSign = new unsigned char[msgToSignLength];
	memmove(msgToSign, nonceC, NONCE_LEN);
	memmove(msgToSign + NONCE_LEN, *serverDhPublicKey, serverDhPublicKeyLength);


	int signatureCompareResult = VerifySign(EVP_sha256(), serverSign, *serverSignLength, msgToSign, msgToSignLength, serverRSAPubKey);
	delete[] serverSignLength;
	delete[] msgToSign;
	delete[] serverSign;
	EVP_PKEY_free(serverRSAPubKey);
	if (signatureCompareResult != 1) {
		std::cerr << "Could not verify sign(nonce(c), A)! Closing connection..." << std::endl;
		SendMessage(sd, HANDSHAKE_ERROR, sizeof(HANDSHAKE_ERROR));
		return NULL;
	}

	SendMessage(sd, HANDSHAKE_ACK, sizeof(HANDSHAKE_ACK));

	// GETS NONCE(S)
	unsigned char* nonceS = NULL;
	if (ReadMessage(sd, NONCE_LEN, &nonceS) == FAIL) {
		std::cerr << "Error receiving server nonce" <<std::endl;
		return NULL;
	}

	return nonceS;
}

unsigned char* ThirdHandShakeMessageHandler(int sd,unsigned char* nonceS, std::string username, unsigned char* peerPublicDHKey, u_int32_t serverDhPublicKeyLength) {

	/**********************************************
	**GENERATE SIGN(nonce(c), publicDh) & SEND IT**
	**********************************************/

	// CREATES PRIVATE & PUBLIC KEY PAIR AND SESSION KEY

	EVP_PKEY* myPrivateKey = GenerateDiffieHellmanPrivateAndPublicPair();
	if (myPrivateKey == NULL) {
		std::cerr << "Error generating private key" << std::endl;
		delete[] peerPublicDHKey;
		return NULL;
	}

	unsigned char* sessionKey = GetDefaultSessionKeyFromPeerPublicAndMyPrivate(myPrivateKey, peerPublicDHKey, serverDhPublicKeyLength);
	if (sessionKey == NULL) {
		std::cerr << "Error generating session key" << std::endl;
		EVP_PKEY_free(myPrivateKey);
		return NULL;
	}


	u_int32_t clientDhPublicKeyLength = -1;
	unsigned char* clientDhPublicKey = ExtractPublicKey("clientDhPublicKey.PEM", myPrivateKey, clientDhPublicKeyLength);
	EVP_PKEY_free(myPrivateKey);
	if (clientDhPublicKey == NULL) {
		std::cerr << "Error extracting public key" << std::endl;
		delete[] sessionKey;
		return NULL;
	}

	if (SendMessage(sd, &clientDhPublicKeyLength, sizeof(uint32_t)) == FAIL || SendMessage(sd, clientDhPublicKey, clientDhPublicKeyLength) == FAIL) {
		std::cerr << "Error sending DiffieHellman public key" << std::endl;
		delete[] sessionKey;
		delete[] clientDhPublicKey;
		return NULL;
	}

	// CONCATS NONCE(S) WITH clientPUBLICDHKEY

	int msgToSignLength = NONCE_LEN + clientDhPublicKeyLength;
	unsigned char* msgToSign = new unsigned char[msgToSignLength];
	memmove(msgToSign, nonceS, NONCE_LEN);
	memmove(msgToSign + NONCE_LEN, clientDhPublicKey, clientDhPublicKeyLength);

	delete[] clientDhPublicKey;


	/**********************************
	**  READ CLIENT RSA PRIVATE KEY  **
	**AND USES IT TO SIGN NONCE AND A**
	**********************************/

	// Removes null terminating characters, otherwise it won't concat correctly
	username = RemoveCharacter(username, ' ');
	username = RemoveCharacter(username, '\0');
	
	std::string clientPrivateRSAKeyFile = username + std::string("/") + username + std::string(".pem");
	EVP_PKEY* clientRSAPrivateKey = ReadRSAPrivateKey(clientPrivateRSAKeyFile.c_str());

	if (clientRSAPrivateKey == NULL || SendMessage(sd, HANDSHAKE_ACK, sizeof(HANDSHAKE_ACK)) == FAIL) {
		std::cerr << "Error loading client private key from disk" << std::endl;
		SendMessage(sd, HANDSHAKE_ERROR, sizeof(HANDSHAKE_ERROR));
		delete[] sessionKey;
		delete[] msgToSign;
		return NULL;
	}

	uint32_t signatureLength = -1;
	unsigned char* msgSigned = ComputeSign(EVP_sha256(), msgToSign, msgToSignLength, signatureLength, clientRSAPrivateKey);
	delete[] msgToSign;
	EVP_PKEY_free(clientRSAPrivateKey);

	
	if (SendMessage(sd, &signatureLength, sizeof(uint32_t)) == FAIL || SendMessage(sd, msgSigned, signatureLength) == FAIL) {
		std::cerr << "Error sending signature " << std::endl;
		delete[] sessionKey;
		delete[] msgSigned;
		return NULL;
	}
	delete[] msgSigned;

	unsigned char* resultOfSignatureValidation = NULL;
	if ( ReadMessage(sd, sizeof(HANDSHAKE_ERROR), &resultOfSignatureValidation) == FAIL || *resultOfSignatureValidation == *HANDSHAKE_ERROR) {
		std::cerr << "Signature was not valid for the server" << std::endl;
		delete[] sessionKey;
		if (resultOfSignatureValidation!=NULL) delete[] resultOfSignatureValidation;
		return NULL;
	}
	delete[] resultOfSignatureValidation;

	return sessionKey;

}

unsigned char* AuthenticateAndNegotiateKey(int sd, std::string& username) {

	unsigned char* nonceC = FirstHandShakeMessageHandler(sd, username);

	if (nonceC == NULL) {
		delete[]nonceC;
		return NULL;
	}
	std::cout << "=====================================================" << std::endl;
	std::cout << "1/3 HandShake messages are successful! Keep it up :) " << std::endl;
	std::cout << "=====================================================" << std::endl;

	unsigned char* diffieHellPublicKey = NULL;
	u_int32_t serverDhPublicKeyLength = -1;

	unsigned char* nonceS = SecondHandShakeMessageHandler(sd, &diffieHellPublicKey, serverDhPublicKeyLength, nonceC);
	std::cout << serverDhPublicKeyLength << std::endl;
	std::cout << diffieHellPublicKey << std::endl;
	delete[]nonceC;
	if (nonceS == NULL) {
		return NULL;
	}

	std::cout << "=====================================================" << std::endl;
	std::cout << "2/3 HandShake messages are successful! Keep it up :) " << std::endl;
	std::cout << "=====================================================" << std::endl;

	unsigned char* x = ThirdHandShakeMessageHandler(sd, nonceS, username, diffieHellPublicKey, serverDhPublicKeyLength);
	delete[]nonceS;

	return x;
	
}

int SelectOperation() {
	std::string inputLine = "0";
	int userInput = 0;

	if (!std::getline(std::cin, inputLine)) {
		std::cerr << "Error reading input from keyboard.. " << std::endl;
	}else {
		try {
			userInput = std::stoi(inputLine);
		}catch (std::exception const & e) {
			std::cerr<<" Error: while elaborating input, a valid input is a positive number!" << std::endl;
		}
	}

	if (userInput > 6 || userInput < 0) userInput = 0;
	return userInput;
}

int UploadOperation(int sd, unsigned char* key, u_int64_t& messageCounter, std::string username) {

	std::cout << "Upload operation selected" << std::endl;
	std::cout << "The file to upload MUST be in the logged user folder, it cannot be anywhere else in the disk" << std::endl;
	std::cout << "Input the filename of the file including the extension: " << std::endl;

	std::string inputFilename;
	std::cin >> inputFilename;

	if (ValidateString(inputFilename, FILENAME_LENGTH) == FAIL) {
		std::cout << "Input filename is not valid " << std::endl;
		return FAIL;	
	}

	username = RemoveCharacter(username, '\0');

	std::string completeFilename = username + '/' + inputFilename;

	FILE* uploadFile = fopen(completeFilename.c_str(), "r");
	if (uploadFile == NULL) {
		std::cout << "File not found" << std::endl;
		return FAIL;
	}

	u_int32_t fileSize = GetFileSize(completeFilename);

	if (fileSize == 0) {
		std::cout << "Invalid file, too big or empty" << std::endl;
		return FAIL;
	}
	fclose(uploadFile);


	// PREPARE AND SEND ASK FOR UPLOAD
	unsigned char *plaintext = (unsigned char *)inputFilename.c_str();
	uint64_t payloadLength = strlen((char*) plaintext); // length = plaintext +1, in questo caso c'è il char di terminazione quindi plaintext
	// Perchè? Perchè - inserisci spiegazione dei blocchi -
	uint32_t numberOfDataBlocks = GetNumberOfDataBlocks(fileSize);
	if (SendOperationPackage(sd, OPERATION_ID_UPLOAD, messageCounter, payloadLength, numberOfDataBlocks, plaintext, key) != 1) {
		std::cout << "Something went wrong preparing or sending operation package.. " <<std::endl;
		return FAIL;
	}

	unsigned char* outBuf = NULL;

	uint64_t decryptedTextLength = 0;

	uint32_t opIdRec = 0;
	uint64_t messageCounterRec = 0;
	uint64_t ciphertextLengthRec = 0;
	uint32_t optVarRec = 0;
	if (ReadOperationPackage(sd, key, opIdRec, messageCounterRec, messageCounter, ciphertextLengthRec, optVarRec, decryptedTextLength, outBuf) != 1) {
		std::cout << "Something went wrong receiving server ack" << std::endl;
		if (outBuf != NULL) delete[] outBuf;
		return FAIL;
	}
	delete[] outBuf;

	if (opIdRec == OPERATION_ID_ABORT) {
		std::cerr << "Upload operation aborted from server" << std::endl;
		return FAIL;
	}

	if (opIdRec!=OPERATION_ID_ACK) {
		std::cerr << "Invalid op code response" << std::endl;
		throw std::invalid_argument("Server answered with invalid op code");
	}

	if (SendFileInOperationPackage(sd, completeFilename, numberOfDataBlocks, fileSize, key, messageCounter, 1) != 1) {
		std::cout << "Upload failed with network error" << std::endl;
		throw std::invalid_argument("Upload failed");
	}
	std::cout << "Upload completed, waiting for server response.." << std::endl;


	if (ReadOperationPackage(sd, key, opIdRec, messageCounterRec, messageCounter, ciphertextLengthRec, optVarRec, decryptedTextLength, outBuf) != 1) {
		std::cout << "Something went wrong receiving server ack" << std::endl;
		throw std::invalid_argument("Upload failed");
	}
	delete[] outBuf;

	if (opIdRec == OPERATION_ID_ABORT) {
		std::cerr << "Upload operation aborted from server" << std::endl;
		return FAIL;
	}

	if (opIdRec!=OPERATION_ID_DONE) {
		std::cerr << "Invalid op code response" << std::endl;
		throw std::invalid_argument("Server answered with invalid op code");
	}

	return 1;

}

int DownloadOperation(int sd, unsigned char* key, u_int64_t& messageCounter, std::string username) {

	std::cout << "Download operation selected" << std::endl;
	std::cout << "The file to download MUST be in the remote logged user folder, it cannot be anywhere else in the disk" << std::endl;
	std::cout << "Input the filename of the file including the extension: " << std::endl;

	std::string inputFilename;
	std::cin >> inputFilename;


	if (ValidateString(inputFilename, FILENAME_LENGTH) == FAIL) {
		std::cout << "Input filename is not valid " << std::endl;
		return FAIL;	
	}
	
	username = RemoveCharacter(username, '\0');
	std::string completeFilename = username + '/' + inputFilename;

	FILE* downloadFile = fopen(completeFilename.c_str(), "r");
	if (downloadFile != NULL) {
		std::cout << "File already exists" << std::endl;
		fclose(downloadFile);
		return FAIL;
	}


	// PREPARE AND SEND ASK FOR DOWNLOAD
	unsigned char *plaintext = (unsigned char *)inputFilename.c_str();
	uint64_t payloadLength = strlen((char*) plaintext); // length = plaintext +1, in questo caso c'è il char di terminazione quindi plaintext
	// Perchè? Perchè - inserisci spiegazione dei blocchi -
	if (SendOperationPackage(sd, OPERATION_ID_DOWNLOAD, messageCounter, payloadLength, 0, plaintext, key) != 1) {
		std::cout << "Something went wrong preparing or sending operation package.. " <<std::endl;
		return FAIL;
	}
	unsigned char* outBuf = NULL;

	uint64_t decryptedTextLength = 0;

	uint32_t opIdRec = 0;
	uint64_t messageCounterRec = 0;
	uint64_t ciphertextLengthRec = 0;
	uint32_t numberOfDataBlocks = 0;

	if (ReadOperationPackage(sd, key, opIdRec, messageCounterRec, messageCounter, ciphertextLengthRec, numberOfDataBlocks, decryptedTextLength, outBuf) != 1) {
		std::cout << "Something went wrong receiving server ack" << std::endl;
		throw std::invalid_argument("Download request failed");
	}

	if (opIdRec == OPERATION_ID_ABORT) {
		std::cerr << "Download operation aborted from server" << std::endl;
		return FAIL;
	}

	if (opIdRec!=OPERATION_ID_ACK) {
		std::cerr << "Invalid op code response" << std::endl;
		throw std::invalid_argument("Server answered with invalid op code");
	}

	SendStatusPackage(sd, key, OPERATION_ID_ACK, messageCounter);
	try {
		ReadFileInOperationPackage(sd, completeFilename, numberOfDataBlocks, key, messageCounter, 1);
	} catch(const std::invalid_argument& e) {
		remove(completeFilename.c_str());
		throw;
	}

	SendStatusPackage(sd, key, OPERATION_ID_DONE, messageCounter);
	return 1;

}

int DeleteOperation(int sd, unsigned char* key, u_int64_t& messageCounter, std::string username) {
	std::cout << "Upload operation selected" << std::endl;
	std::cout << "The file to upload MUST be in the logged user folder, it cannot be anywhere else in the disk" << std::endl;
	std::cout << "Input the filename of the file including the extension: " << std::endl;

	std::string inputFilename;
	std::cin >> inputFilename;

	if (ValidateString(inputFilename, FILENAME_LENGTH) == FAIL) {
		std::cout << "Input filename is not valid " << std::endl;
		return FAIL;	
	}

	username = RemoveCharacter(username, '\0');

	std::string completeFilename = username + '/' + inputFilename;

	FILE* deleteFile = fopen(completeFilename.c_str(), "r");
	if (deleteFile == NULL) {
		std::cout << "File not found" << std::endl;
		return FAIL;
	}

	fclose(deleteFile);


	// PREPARE AND SEND ASK FOR DELETE
	unsigned char *plaintext = (unsigned char *)inputFilename.c_str();
	uint64_t payloadLength = strlen((char*) plaintext); // length = plaintext +1, in questo caso c'è il char di terminazione quindi plaintext
	// Perchè? Perchè - inserisci spiegazione dei blocchi -
	uint32_t numberOfDataBlocks = 0;
	if (SendOperationPackage(sd, OPERATION_ID_DELETE, messageCounter, payloadLength, numberOfDataBlocks, plaintext, key) != 1) {
		std::cout << "Something went wrong preparing or sending operation package.. " <<std::endl;
		return FAIL;
	}

	unsigned char* outBuf = NULL;

	uint64_t decryptedTextLength = 0;

	uint32_t opIdRec = 0;
	uint64_t messageCounterRec = 0;
	uint64_t ciphertextLengthRec = 0;
	uint32_t optVarRec = 0;
	if (ReadOperationPackage(sd, key, opIdRec, messageCounterRec, messageCounter, ciphertextLengthRec, optVarRec, decryptedTextLength, outBuf) != 1) {
		std::cout << "Something went wrong receiving server ack" << std::endl;
		if (outBuf != NULL) delete[] outBuf;
		return FAIL;
	}
	delete[] outBuf;

	if (opIdRec == OPERATION_ID_ABORT) {
		std::cerr << "Download operation aborted from server" << std::endl;
		return FAIL;
	}

	if (opIdRec!=OPERATION_ID_DONE) {
		std::cerr << "Invalid op code response" << std::endl;
		throw std::invalid_argument("Server answered with invalid op code");
	}

	return 1;

}

int ListOperation(int sd, unsigned char* key, u_int64_t& messageCounter) {
	std::cout << "List operation selected" << std::endl;

	// PREPARE AND SEND ASK FOR LIST
	unsigned char *plaintext = (unsigned char *)"0";
	uint64_t payloadLength = strlen((char*) plaintext); // length = plaintext +1, in questo caso c'è il char di terminazione quindi plaintext
	// Perchè? Perchè - inserisci spiegazione dei blocchi -
	uint32_t numberOfDataBlocks = 0;
	if (SendOperationPackage(sd, OPERATION_ID_LIST, messageCounter, payloadLength, numberOfDataBlocks, plaintext, key) != 1) {
		std::cout << "Something went wrong preparing or sending operation package.. " <<std::endl;
		return FAIL;
	}

	unsigned char* outBuf = NULL;

	uint64_t decryptedTextLength = 0;

	uint32_t opIdRec = 0;
	uint64_t messageCounterRec = 0;
	uint64_t ciphertextLengthRec = 0;
	uint32_t optVarRec = 0;
	if (ReadOperationPackage(sd, key, opIdRec, messageCounterRec, messageCounter, ciphertextLengthRec, optVarRec, decryptedTextLength, outBuf) != 1 || opIdRec != OPERATION_ID_DATA) {
		std::cout << "Something went wrong server response" << std::endl;
		if (outBuf != NULL) delete[] outBuf;
		return FAIL;
	}
	std::vector<std::string> fileVector = SplitBufferByCharacter((char*) outBuf, ',');
	std::cout << "LIST OF FILES SAVED TO SERVER:" << std::endl;
	for (const auto & entry: fileVector) {
		if (ValidateString(entry, FILENAME_LENGTH) == 1) std::cout << "|--" << entry << std::endl;
	}
	
	delete[] outBuf;
	return 1;
}

int RenameOperation(int sd, unsigned char* key, u_int64_t& messageCounter) {

	std::vector<std::string> fileList;
	std::cout << "Rename operation selected" << std::endl;
	std::cout << "The file to rename MUST be in the remote logged user folder" << std::endl;
	std::cout << "Input the filename of the file to rename including the extension: " << std::endl;

	std::string inputFilename;
	std::cin >> inputFilename;

	if (ValidateString(inputFilename, FILENAME_LENGTH) == FAIL) {
		std::cout << "Input old filename is not valid " << std::endl;
		return FAIL;	
	}

	fileList.push_back(RemoveCharacter(inputFilename, '\0'));

	std::cout << "Enter the new filename" << std::endl;
	std::string newFilename;
	std::cin >> newFilename;

	if (ValidateString(newFilename, FILENAME_LENGTH) == FAIL) {
		std::cout << "Input new filename is not valid " << std::endl;
		return FAIL;	
	}

	fileList.push_back(RemoveCharacter(newFilename, '\0'));

	std::string toSendString = ConcatenateFileNames(fileList, ",");
	// PREPARE AND SEND ASK FOR RENAME

	
	unsigned char *plaintext = (unsigned char *)toSendString.c_str();
	uint64_t payloadLength = strlen((char*) plaintext); // length = plaintext +1, in questo caso c'è il char di terminazione quindi plaintext
	// Perchè? Perchè - inserisci spiegazione dei blocchi -
	uint32_t numberOfDataBlocks = 0;
	if (SendOperationPackage(sd, OPERATION_ID_RENAME, messageCounter, payloadLength, numberOfDataBlocks, plaintext, key) != 1) {
		std::cout << "Something went wrong preparing or sending operation package.. " <<std::endl;
		return FAIL;
	}


	unsigned char* outBuf = NULL;

	uint64_t decryptedTextLength = 0;

	uint32_t opIdRec = 0;
	uint64_t messageCounterRec = 0;
	uint64_t ciphertextLengthRec = 0;
	uint32_t optVarRec = 0;
	if (ReadOperationPackage(sd, key, opIdRec, messageCounterRec, messageCounter, ciphertextLengthRec, optVarRec, decryptedTextLength, outBuf) != 1) {
		std::cout << "Something went wrong server response" << std::endl;
		if (outBuf != NULL) delete[] outBuf;
		return FAIL;
	}

	delete [] outBuf;

	if (opIdRec == OPERATION_ID_ABORT) {
		std::cerr << "Download operation aborted from server" << std::endl;
		return FAIL;
	}

	if (opIdRec!=OPERATION_ID_DONE) {
		std::cerr << "Invalid op code response" << std::endl;
		throw std::invalid_argument("Server answered with invalid op code");
	}

	return 1;
}

int LogoutOperation(int sd, unsigned char* key, u_int64_t& messageCounter) {
	return FAIL;
}


void AuthenticatedUserMainLoop(int sd, unsigned char* sessionKey, std::string username) {
	// Initialize messageCounter
	uint64_t messageCounter = 0;


	uint32_t operationID = 0;
	// TODO UMH A TRY CATCH THIS BIG, SURELY THIS CANNOT BE BAD PROGRAMMING
	try {
		while (true) {
			operationID = SelectOperation();
			switch(operationID) {
				case 1:
					if (UploadOperation(sd, sessionKey, messageCounter, username) == FAIL) {
						PrettyUpPrintToConsole("Upload operation failed");
					} else {
						PrettyUpPrintToConsole("Upload operation completed");
					}
					break;
				case 2:
					if (DownloadOperation(sd, sessionKey, messageCounter, username) == FAIL) {
						PrettyUpPrintToConsole("Download operation failed");
					} else {
						PrettyUpPrintToConsole("Download operation completed");
					}
					break;
				case 3:
					if (DeleteOperation(sd, sessionKey, messageCounter, username) == FAIL) {
						PrettyUpPrintToConsole("Delete operation failed");
					} else {
						PrettyUpPrintToConsole("Delete operation completed");
					}
					break;
				case 4:
					if (ListOperation(sd, sessionKey, messageCounter) == FAIL) {
						PrettyUpPrintToConsole("List operation failed");
					} else {
						PrettyUpPrintToConsole("List operation completed");
					}
					break;
				case 5:
					if (RenameOperation(sd, sessionKey, messageCounter) == FAIL) {
						PrettyUpPrintToConsole("Rename operation failed");
					} else {
						PrettyUpPrintToConsole("Rename operation completed");
					}
					break;
				case 6:
					if (LogoutOperation(sd, sessionKey, messageCounter) == FAIL) {
						PrettyUpPrintToConsole("Logout operation failed");
					} else {
						PrettyUpPrintToConsole("Logout operation completed");
					}
					break;
				default:
					PrintListOfOperations();
					break;
			}

		}
	}catch(const std::invalid_argument& e) {
		std::cerr << e.what() << std::endl;
		return;
	}

}


int OpenConnection(const char *hostname, int port) {
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;

	if ( (host = gethostbyname(hostname)) == NULL )
	{
		perror(hostname);
		abort();
	}

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);

	if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) == FAIL )
	{
		close(sd);
		perror(hostname);
		abort();
	}

	return sd;
}


int main(int args_count, char *args[]) {
	char *hostname, *portstr;
	int portnum;
	int sd;

	if (args_count != 3) {
		printf("Missing arguments in the execution, both ip and port number are required \n");
		exit(1);
	}

	hostname=args[1];
	portstr=args[2];
	portnum = atoi(portstr);

	if (portnum == 0) { //|| portnum == 80) {
		printf("Input port is not a valid number \n");
		exit(1);
	}

	sd = OpenConnection(hostname, portnum);

	printf("Connected with hostname %s and port %s \n", hostname, portstr);


	/*******************
	** STARTUP ART :) **
	*******************/

	std::string welcomeFile = "start_client_art.txt";
	std::cout<<ReadFile(welcomeFile) << std::endl;


	// HANDSHAKE
	std::string username = "Kurisu Makise";
	unsigned char* sessionKey = AuthenticateAndNegotiateKey(sd, username);

	if (sessionKey==NULL) {
		std::cout << std::string("=====================================================") << std::endl;
		std::cout << std::string("Handshake aborted .. Retry later .. I'm sorry mate :(") << std::endl;
		std::cout << std::string("=====================================================") << std::endl;
		close(sd);
		return -1;
	} else {

		printf("\033c"); // For Linux/Unix and maybe some others but not for Windows before 10 TH2 will reset terminal

		/*************************
		** LOGIN SUCCESS ART :) **
		**************************/

		std::string handshakeSuccessFile = "login_success_art.txt";
		std::cout<<ReadFile(handshakeSuccessFile) << std::endl;

		BIO_dump_fp (stdout, (const char *)sessionKey, 16);

		AuthenticatedUserMainLoop(sd, sessionKey, username);

		ClearBufferArea(sessionKey, DH_KEY_LENGTH);
	}




	return 0;
}
