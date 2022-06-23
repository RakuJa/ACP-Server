// Daniele Giachetto - Foundation of Cybersecurity Project


#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include "../lib/header/utils.h"
#include "../lib/header/hash.h"
#include "../lib/header/certificate.h"
#include "../lib/header/key_handle.h"
#include <sstream>

int isUsernameRegistered(const char *sentence, std::string username) {

  	std::stringstream ss(sentence);
  	std::string to;

  	if (sentence != NULL) {
    	while(std::getline(ss,to,'\n')) {
			if (username == to) {
				return 1;
			}
    	}
  	}
	return FAIL;
}

int OpenListener(int port)
{
	int sd;
	struct sockaddr_in addr;
	sd = socket(PF_INET, SOCK_STREAM, 0);

	bzero(&addr, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		std::cerr<<"PORT BINDING ERROR";
		close(sd);
		abort();
	}

	if ( listen(sd, 10) != 0 )
	{
		std::cerr<<"LISTENING PORT CONFIGURATION PROBLEM";
		close(sd);
		abort();
	}
	return sd;
}



/**
 * @brief Receive the login message from the client, returns NULL if login failed (username refused) or could not get nonce
 * 
 * @param usernamename will be used to return the username that succeded login
 * @return unsigned* the nonce received from the client or NULL if login failed or could not get nonce
 */
unsigned char* FirstHandShakeMessageHandler(int sd, std::string & sName) {
	
	//                FIRST MESSAGE                //
	/************************************************
	** GET NONCE, GET USERNAME & VALIDATE USERNAME **
	*************************************************/

	char* username = NULL;

	if (ReadMessage(sd, USERNAME_MAX_LENGTH, &username) == FAIL) {
		std::cerr << "Error receiving username" <<std::endl;
		return NULL;
	}

	sName = std::string(username, USERNAME_MAX_LENGTH);
	sName = RemoveCharacter(sName, ' ');
	sName = RemoveCharacter(sName, '\0');

	delete[] username;

	std::string clientListFile = "client_list.txt";

	if (ValidateString(sName, USERNAME_MAX_LENGTH) == FAIL || isUsernameRegistered(ReadFile(clientListFile).c_str(), sName) == FAIL) {
		std::cout<<"Error validating username: " << sName << std::endl;
		SendMessage(sd, HANDSHAKE_ERROR, sizeof(HANDSHAKE_ERROR));
		return NULL;
	}

	unsigned char* nonceC = NULL;
	if (ReadMessage(sd, NONCE_LEN, &nonceC) == FAIL) {
		std::cout <<"Failed to fetch client nonce " << std::endl;
		SendMessage(sd, HANDSHAKE_ERROR, sizeof(HANDSHAKE_ERROR));
		return NULL;
	}

	// Send ack or abort
	SendMessage(sd, HANDSHAKE_ACK, sizeof(HANDSHAKE_ACK));

	return nonceC;

}


/**
 * @brief Sends certificate, A, nonce(s), sign(nonce(c), A) and checks the client responses.
 * 
 * @param sd socket to receive and send messages from
 * @param myPrivateKey will be used to return the privateDHKey
 * @param nonceC client nonce that will be concatenated with A and signed
 * @return unsigned* the generated nonce sent to the client or NULL if something went wrong
 */
unsigned char* SecondHandShakeMessageHandler(int sd, unsigned char* nonceC, EVP_PKEY** myPrivateKey) {

	//                 SECOND MESSAGE                 //
	/***************************************************
	**SEND CERTIFICATE, A, NONCE(S), SIGN(NONCE(C), A)**
	***************************************************/
	std::string serverCer = ReadFile(SERVER_CERT_NAME);

	// send server certificate 
	uint32_t certLength = serverCer.length();
	if (SendMessage(sd, &certLength, sizeof(uint32_t)) == FAIL || SendMessage(sd, serverCer.c_str(), serverCer.length()) == FAIL) {
		std::cerr << "Error sending certificate " << std::endl;
		return NULL;
	}

	unsigned char* resultOfCertificateValidation = NULL;
	if (ReadMessage(sd, sizeof(HANDSHAKE_ERROR), &resultOfCertificateValidation) == FAIL || *resultOfCertificateValidation == *HANDSHAKE_ERROR) {
		std::cerr << "Certificate was not valid for the client" << std::endl;
		delete[] resultOfCertificateValidation;
		return NULL;
	}
	delete[] resultOfCertificateValidation;

	/**********************************************
	**GENERATE SIGN(nonce(c), publicDh) & SEND IT**
	**********************************************/

	// CREATES PRIVATE & PUBLIC KEY PAIR

	*myPrivateKey = GenerateDiffieHellmanPrivateAndPublicPair();
	if (myPrivateKey == NULL) {
		std::cerr << "Error generating private key" << std::endl;
		return NULL;
	}

	u_int32_t serverDhPublicKeyLength = -1;
	unsigned char* serverDhPublicKey = ExtractPublicKey("serverDhPublicKey.PEM", *myPrivateKey, serverDhPublicKeyLength);

	if (serverDhPublicKey == NULL) {
		std::cerr << "Error extracting public key" << std::endl;
		EVP_PKEY_free(*myPrivateKey);
		return NULL;
	}

	if (SendMessage(sd, &serverDhPublicKeyLength, sizeof(uint32_t)) == FAIL || SendMessage(sd, serverDhPublicKey, serverDhPublicKeyLength) == FAIL) {
		std::cerr << "Error sending DiffieHellman public key" << std::endl;
		EVP_PKEY_free(*myPrivateKey);
		delete[] serverDhPublicKey;
		return NULL;
	}

	// CONCATS NONCE(C) WITH serverPUBLICDHKEY
	//std::basic_string<unsigned char> msgToSign = std::basic_string<unsigned char>(nonceC) + std::basic_string<unsigned char>(serverDhPublicKey);

	int msgToSignLength = NONCE_LEN + serverDhPublicKeyLength;
	unsigned char* msgToSign = new unsigned char[msgToSignLength];
	memmove(msgToSign, nonceC, NONCE_LEN);
	memmove(msgToSign + NONCE_LEN, serverDhPublicKey, serverDhPublicKeyLength);

	/**********************************
	**  READ SERVER RSA PRIVATE KEY  **
	**AND USES IT TO SIGN NONCE AND A**
	**********************************/

	EVP_PKEY* serverRSAPrivateKey = ReadRSAPrivateKey("ServerRSAPrivate.pem");

	if (serverRSAPrivateKey == NULL) {
		std::cerr << "Error loading server private key from disk" << std::endl;
		EVP_PKEY_free(*myPrivateKey);
		delete[] serverDhPublicKey;
		return NULL;
	}

	uint32_t signatureLength = -1;
	unsigned char* msgSigned = ComputeSign(EVP_sha256(), msgToSign, msgToSignLength, signatureLength, serverRSAPrivateKey);
	delete[] msgToSign;
	
	if (SendMessage(sd, &signatureLength, sizeof(uint32_t)) == FAIL || SendMessage(sd, msgSigned, signatureLength) == FAIL) {
		std::cerr << "Error sending signature " << std::endl;
		EVP_PKEY_free(*myPrivateKey);
		EVP_PKEY_free(serverRSAPrivateKey);
		delete[] serverDhPublicKey;
		return NULL;
	}

	unsigned char* resultOfSignatureValidation = NULL;
	if (ReadMessage(sd, sizeof(HANDSHAKE_ERROR), &resultOfSignatureValidation) == FAIL || *resultOfSignatureValidation == *HANDSHAKE_ERROR) {
		std::cerr << "Signature was not valid for the client" << std::endl;
		EVP_PKEY_free(*myPrivateKey);
		EVP_PKEY_free(serverRSAPrivateKey);
		delete[]resultOfSignatureValidation;
		delete[] serverDhPublicKey;
		return NULL;
	}
	delete[] resultOfSignatureValidation;

	/***************************
	**GENERATE NONCE & SEND IT**
	***************************/

	// Nonce(s) generation
	unsigned char* nonceS = new unsigned char[NONCE_LEN];
	if (nonceS == NULL) {
		std::cerr<<"Could not allocate memory for nonce(s)" << std::endl;
		EVP_PKEY_free(*myPrivateKey);
		delete[] serverDhPublicKey;
		return NULL;
	}

	if (RandomGenerator(nonceS, NONCE_LEN) == FAIL || SendMessage(sd, nonceS, NONCE_LEN) == FAIL) {
		std::cerr<<"Failure while generating or sending nonce(s)" << std::endl;
		EVP_PKEY_free(*myPrivateKey);
		delete[]nonceS;
		delete[] serverDhPublicKey;
		return NULL;
	}

	
	delete[] serverDhPublicKey;
	return nonceS;
}

unsigned char* ThirdHandShakeMessageHandler(int sd, unsigned char* nonceS, std::string username, EVP_PKEY* myPrivateKey) {
	
	// GET B (clientPublicDhKey) LENGTH
	uint32_t* clientDhPublicKeyLength = NULL;
	if (ReadMessage(sd, sizeof(u_int32_t), &clientDhPublicKeyLength) == FAIL) {
		std::cerr << "DiffieHellman public key length received is invalid" << std::endl;
		return NULL;
	}

	// GET B (clientPublicDhKey)
	unsigned char* clientDhPublicKey = NULL;
	int fetchDHResult = ReadMessage(sd, *clientDhPublicKeyLength, &clientDhPublicKey);
	if (fetchDHResult == FAIL) {
		std::cerr << "Failure while receiving DiffieHellman public key" << std::endl;
		delete[] clientDhPublicKeyLength;
		return NULL;
	}

	// CHECK IF CLIENT DID LOAD CORRECTLY KEY FROM DISK
	unsigned char* resultOfClientLoadKey = NULL;
	if (ReadMessage(sd, sizeof(HANDSHAKE_ERROR), &resultOfClientLoadKey) == FAIL || *resultOfClientLoadKey == *HANDSHAKE_ERROR) {
		std::cerr << "Client failed to load private key" << std::endl;
		delete[] clientDhPublicKeyLength;
		return NULL;
	}

	// READ SIGNATURE

	u_int32_t* clientSignLength = NULL;
	if (ReadMessage(sd, sizeof(u_int32_t), &clientSignLength) == FAIL) {
		std::cerr << "Client signature length received is invalid" << std::endl;
		delete[] clientDhPublicKeyLength;
		delete[] clientDhPublicKey;
		return NULL;
	}


	unsigned char* clientSign = NULL;
	if (ReadMessage(sd, *clientSignLength, &clientSign) == FAIL) {
		std::cerr << "Failed while receiving signature" << std::endl;
		delete[] clientSignLength;
		delete[] clientDhPublicKeyLength;
		delete[] clientDhPublicKey;
		return NULL;
	}

	// Read Client public key

	std::string clientKeysFolder = "ClientsPubKey/";
	EVP_PKEY* clientRSAPubKey = ReadRSAPublicKey((clientKeysFolder + username + ".pem").c_str());


	// Sign (NONCE(S) + B)


	int msgToSignLength = NONCE_LEN + *clientDhPublicKeyLength;
	unsigned char* msgToSign = new unsigned char[msgToSignLength];
	memmove(msgToSign, nonceS, NONCE_LEN);
	memmove(msgToSign + NONCE_LEN, clientDhPublicKey, *clientDhPublicKeyLength);

	

	int signatureCompareResult = VerifySign(EVP_sha256(), clientSign, *clientSignLength, msgToSign, msgToSignLength, clientRSAPubKey);
	delete[] clientSignLength;
	delete[] msgToSign;
	delete[] clientSign;
	EVP_PKEY_free(clientRSAPubKey);
	if (signatureCompareResult != 1) {
		std::cerr << "Could not verify sign(nonce(s), B)! Closing connection..." << std::endl;
		SendMessage(sd, HANDSHAKE_ERROR, sizeof(HANDSHAKE_ERROR));
		return NULL;
	}

	if (SendMessage(sd, HANDSHAKE_ACK, sizeof(HANDSHAKE_ACK)) == FAIL) {
		std::cerr << "Error sending final ACK" << std::endl;
		return NULL;
	}

	// Generate Kab and Key
	
	unsigned char* sessionKey = GetDefaultSessionKeyFromPeerPublicAndMyPrivate(myPrivateKey, clientDhPublicKey, *clientDhPublicKeyLength);
	if (sessionKey == NULL) {
		std::cerr << "Error generating session key" << std::endl;
		EVP_PKEY_free(myPrivateKey);
		return NULL;
	}


	delete[] clientDhPublicKeyLength;
	return sessionKey;

}



unsigned char* AuthenticateAndNegotiateKey(int sd, std::string& username) {

	/***********************
	**GET USERNAME & NONCE**
	***********************/

	/***************************************
	**READ CERTIFICATE FROM DISK & SEND IT**
	****************************************/

	username = "";
	unsigned char* nonceC = FirstHandShakeMessageHandler(sd, username);
	if (nonceC==NULL) {
		return NULL;
	}

	std::cout << std::string("=====================================================") << std::endl;
	std::cout << std::string("Handshake aborted .. Retry later .. I'm sorry mate :(") << std::endl;
	std::cout << std::string("=====================================================") << std::endl;

	EVP_PKEY* myPrivateKey = NULL;
	unsigned char* nonceS = SecondHandShakeMessageHandler(sd, nonceC, &myPrivateKey);
	delete[] nonceC;
	if (nonceS == NULL) {
		return NULL;
	}

	std::cout << std::string("=====================================================") << std::endl;
	std::cout << std::string("2/3 HandShake messages are successful! Keep it up :) ") << std::endl;
	std::cout << std::string("=====================================================") << std::endl;

	
	unsigned char* key = ThirdHandShakeMessageHandler(sd, nonceS, username, myPrivateKey);
	delete[] nonceS;

	return key;

}
















int UploadOperation(int sd, unsigned char* key, u_int64_t& messageCounter, uint64_t& filenameLength, uint32_t numberOfDataBlocks, unsigned char* filename, std::string username) {

	char* inputFilename = (char*) filename;
	if (ValidateString(inputFilename, FILENAME_LENGTH) != 1) {
		std::cout << "Invalid filename, abort connection (modified client)" << std::endl;
		ClearBufferArea(key, DH_KEY_LENGTH);
		delete[] filename;
		abort();
	}
	username = RemoveCharacter(username, '\0');
	std::string completeFilename = username + '/' + inputFilename;

	if (CheckFileExistance(completeFilename) != FAIL) {
		std::cout << "File already exists" << std::endl;
		if (SendStatusPackage(sd, key, OPERATION_ID_ABORT, messageCounter) != 1) {
			std::cout << "Error sending abort message, closing connection .." << std::endl;
			ClearBufferArea(key, DH_KEY_LENGTH);
			delete[] filename;
			abort();
		}
		return FAIL;
	}
	std::cout << "Message counter before ack:" << messageCounter << std::endl;
	if (SendStatusPackage(sd, key, OPERATION_ID_ACK, messageCounter) != 1) {
		std::cout << "Failed at sending ack package" << std::endl;
	}

	return 1;

}

int DownloadOperation(int sd, unsigned char* key, u_int64_t& messageCounter, std::string username) {
	return FAIL;
}

int DeleteOperation(int sd, unsigned char* key, u_int64_t& messageCounter, std::string username) {
	return FAIL;
}

int ListOperation(int sd, unsigned char* key, u_int64_t& messageCounter, std::string username) {
	return FAIL;
}

int RenameOperation(int sd, unsigned char* key, u_int64_t& messageCounter, std::string username) {
	return FAIL;
}

int LogoutOperation(int sd, unsigned char* key, u_int64_t& messageCounter) {
	return FAIL;
}



void AuthenticatedUserServerHandlerMainLoop(int sd, unsigned char* sessionKey, std::string username) {
	// Initialize messageCounter
	uint64_t messageCounter = 0;

	unsigned char* decryptedPayload = NULL;

	uint64_t decryptedPayloadLength = 0;

	uint32_t opIdRec = 0;
	uint64_t messageCounterRec = 0;
	uint64_t ciphertextLengthRec = 0;
	uint32_t optVarRec = 0;
	while (true) {

		decryptedPayload = NULL;
		decryptedPayloadLength = 0;
		opIdRec = 0;
		messageCounterRec = 0;
		ciphertextLengthRec = 0;
		optVarRec = 0;

		if (ReadOperationPackage(sd, sessionKey, opIdRec, messageCounterRec, ciphertextLengthRec, optVarRec, decryptedPayloadLength, decryptedPayload) != 1) {
			std::cout << "Error reading client request, abort connection.." << std::endl;
			delete[] decryptedPayload;
			break;
		}

		if (opIdRec > 6 || opIdRec < 1) {
			std::cout<< "Client sent an invalid operation id, abort connection.. " << std::endl;
			delete[] decryptedPayload;
			break;
		}

		if (messageCounter != messageCounterRec) {
			std::cout << "Client sent an invalid message counter, abort connection.." << std::endl;
			delete[] decryptedPayload;
			break;
		}
		messageCounter +=1;

		switch(opIdRec) {
			case 1:
				if (UploadOperation(sd, sessionKey, messageCounter, decryptedPayloadLength, optVarRec, decryptedPayload, username) == FAIL) {
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
				if (ListOperation(sd, sessionKey, messageCounter, username) == FAIL) {
					PrettyUpPrintToConsole("List operation failed");
				} else {
					PrettyUpPrintToConsole("List operation completed");
				}
				break;
			case 5:
				if (RenameOperation(sd, sessionKey, messageCounter, username) == FAIL) {
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
		}
		delete[] decryptedPayload;

	}

}







void* ConnectionHandler(void* socket) {


	std::string username = "";
	int sd = *((int*)socket);

	unsigned char* sessionKey = AuthenticateAndNegotiateKey(sd, username);
	
	if (sessionKey==NULL) {
		std::cout << std::string("=====================================================") << std::endl;
		std::cout << std::string("Last step of the handshake failed.. I'm sorry mate :(") << std::endl;
		std::cout << std::string("=====================================================") << std::endl;
	}else {
		printf("\033c"); // For Linux/Unix and maybe some others but not for Windows before 10 TH2 will reset terminal
		std::cout << std::string("=====================================================") << std::endl;
		std:: cout << "User: " << username << " just logged in! :)" << std::endl;
		std::cout << std::string("=====================================================") << std::endl;
		BIO_dump_fp (stdout, (const char *)sessionKey, 16);
		AuthenticatedUserServerHandlerMainLoop(sd, sessionKey, username);
		ClearBufferArea(sessionKey, DH_KEY_LENGTH); 
	}
	return NULL;
	
}





int main(int count, char *strings[])
{
	int server;
	int portnum = 0;
	pthread_t thread_id;

	if ( count != 2 )
	{
		printf("Missing arguments in the execution, port number is required \n");
		exit(0);
	}

	portnum = atoi(strings[1]);

	if (portnum==0) {
		printf("Input port is not a valid number \n");
		exit(1);
	}

	server = OpenListener(portnum);
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	/*******************
	** STARTUP ART :) **
	*******************/

	std::string welcomeFile = "start_server_art.txt";
	std::cout<<ReadFile(welcomeFile) << std::endl;

	while(1) {

		listen(server,5);

		int client = accept(server, (struct sockaddr*)&addr, &len);

		printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

		if (pthread_create(&thread_id, NULL, ConnectionHandler, (void*)&client)) {
			std::cout << "Error starting connection handler thread... did you compile with the right flag?" << std::endl;
			close(client);
		}else {
			pthread_detach(thread_id);
		}

	}
	
	close(server);

	return 0;

}
