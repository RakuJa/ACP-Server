// Daniele Giachetto - Foundation of Cybersecurity Project


#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
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

	if (ParseString(sName) == FAIL || isUsernameRegistered(ReadFile(clientListFile).c_str(), sName) == FAIL) {
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

	EVP_PKEY* clientRSAPubKey = ReadRSAPublicKey(FromPublicKeyFileNameToPath(username + ".pem").c_str());


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
	std::cout << std::string("1/3 HandShake messages are successful! Keep it up :) ") << std::endl;
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

int main(int count, char *strings[])
{
	int server;
	int portnum;

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

	listen(server,5);

	int client = accept(server, (struct sockaddr*)&addr, &len);

	printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	std::string username = "";
	unsigned char* sessionKey = AuthenticateAndNegotiateKey(client, username);
	
	if (sessionKey==NULL) {
		std::cout << std::string("=====================================================") << std::endl;
		std::cout << std::string("Last step of the handshake failed.. I'm sorrry mate :( ") << std::endl;
		std::cout << std::string("=====================================================") << std::endl;
	}else {
		printf("\033c"); // For Linux/Unix and maybe some others but not for Windows before 10 TH2 will reset terminal
		std::cout << std::string("=====================================================") << std::endl;
		std:: cout << "User: " << username << " just logged in! :)" << std::endl;
		std::cout << std::string("=====================================================") << std::endl;
	}

	std::cout << sessionKey << std::endl;

	delete[] sessionKey;

	close(client);
	close(server);

	return 0;

}
