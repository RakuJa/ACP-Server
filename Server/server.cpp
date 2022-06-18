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

	unsigned char* username = ReadMessage(sd, USERNAME_MAX_LENGTH);

	sName = ConvertFromUnsignedCharToString(username, USERNAME_MAX_LENGTH);
	sName = RemoveCharacter(sName, ' ');
	sName = RemoveCharacter(sName, '\0');
	std::cout<<sName<< '\n';

	if (parse_string(sName) == -1) {
		std::cout<<"Fallita la validazione dello username: " << sName << '\n';
		SendMessage(sd, HANDSHAKE_ERROR, sizeof(HANDSHAKE_ERROR));
		return NULL;
	}
	unsigned char* nonceC = ReadMessage(sd, NONCE_LEN);

	if (nonceC == NULL) {
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
unsigned char* SecondHandShakeMessageHandler(int sd, EVP_PKEY* myPrivateKey, unsigned char* nonceC) {

	//                 SECOND MESSAGE                 //
	/***************************************************
	**SEND CERTIFICATE, A, NONCE(S), SIGN(NONCE(C), A)**
	***************************************************/
	std::string serverCer = ReadFile(SERVER_CERT_NAME);

	// send server certificate 
	if (SendMessage(sd, std::to_string(serverCer.length()).c_str(), sizeof(uint32_t)) == FAIL || SendMessage(sd, serverCer.c_str(), serverCer.length()) == FAIL) {
		std::cerr << "Error sending certificate " << std::endl;
		return NULL;
	}

	unsigned char resultOfCertificateValidation = *ReadMessage(sd, sizeof(HANDSHAKE_ERROR));
	if (resultOfCertificateValidation == *HANDSHAKE_ERROR) {
		std::cerr << "Certificate was not valid for the client" << std::endl;
		return NULL;
	}

	/**************************
	**GENERATE SIGN & SEND IT**
	***************************/

	myPrivateKey = GenerateDiffieHellmanPrivateAndPublicPair();
	if (myPrivateKey == NULL) {
		std::cerr << "Error generating private key" << std::endl;
		return NULL;
	}

	u_int32_t serverDhPublicKeyLength = 0;
	unsigned char* serverDhPublicKey = ExtractPublicKey("ServerDhPublicKey.PEM", myPrivateKey, serverDhPublicKeyLength);

	if (serverDhPublicKey == NULL) {
		std::cerr << "Error extracting public key" << std::endl;
		EVP_PKEY_free(myPrivateKey);
		return NULL;
	}

	if (SendMessage(sd, std::to_string(serverDhPublicKeyLength).c_str(), sizeof(uint32_t)) == FAIL || SendMessage(sd, serverDhPublicKey, serverDhPublicKeyLength) == FAIL) {
		std::cerr << "Error sending DiffieHellman public key" << std::endl;
		EVP_PKEY_free(myPrivateKey);
		return NULL;
	}

	// CONCATS NONCE(C) WITH PEERPUBLICDHKEY
	std::basic_string<unsigned char> msgToSign = std::basic_string<unsigned char>(nonceC) + std::basic_string<unsigned char>(serverDhPublicKey);


	/**********************************
	**  READ SERVER RSA PRIVATE KEY  **
	**AND USES IT TO SIGN NONCE AND A**
	**********************************/

	EVP_PKEY* serverRSAPrivateKey = ReadRSAPrivateKey("ServerRSAPrivate.pem");

	if (serverRSAPrivateKey == NULL) {
		std::cerr << "Error loading server private key from disk" << std::endl;
		EVP_PKEY_free(myPrivateKey);
		return NULL;
	}

	uint32_t signatureLength = 0;
	unsigned char* msgSigned = ComputeSign(EVP_sha256(), msgToSign.c_str(), msgToSign.length(), signatureLength, serverRSAPrivateKey);
	
	if (SendMessage(sd, std::to_string(signatureLength).c_str(), sizeof(uint32_t)) == FAIL || SendMessage(sd, msgSigned, signatureLength) == FAIL) {
		std::cerr << "Error sending signature " << std::endl;
		EVP_PKEY_free(myPrivateKey);
		return NULL;
	}

	unsigned char resultOfSignatureValidation = *ReadMessage(sd, sizeof(HANDSHAKE_ERROR));
	if (resultOfSignatureValidation == *HANDSHAKE_ERROR) {
		std::cerr << "Signature was not valid for the client" << std::endl;
		EVP_PKEY_free(myPrivateKey);
		return NULL;
	}

	/***************************
	**GENERATE NONCE & SEND IT**
	***************************/

	// Nonce(s) generation
	unsigned char* nonceS = (unsigned char*)malloc(NONCE_LEN);
	if (nonceS == NULL) {
		std::cerr<<"Could not allocate memory for nonce(s)" << std::endl;
		EVP_PKEY_free(myPrivateKey);
		return NULL;
	}

	if (RandomGenerator(nonceS, NONCE_LEN) == FAIL || SendMessage(sd, nonceS, NONCE_LEN) == FAIL) {
		std::cerr<<"Failure while generating or sending nonce(s)" << std::endl;
		EVP_PKEY_free(myPrivateKey);
		free(nonceS);
		return NULL;
	}

	return nonceS;
}



unsigned char* AuthenticateAndNegotiateKey(int sd) {

	/***********************
	**GET USERNAME & NONCE**
	***********************/

	/***************************************
	**READ CERTIFICATE FROM DISK & SEND IT**
	****************************************/

	std::string username = "Rintaro Okabe";
	unsigned char* nonceC = FirstHandShakeMessageHandler(sd, username);
	if (nonceC==NULL) {
		return NULL;
	}

	std::cout << "=====================================================" << std::endl;
	std::cout << "1/3 HandShake messages are successful! Keep it up :) " << std::endl;
	std::cout << "=====================================================" << std::endl;

	EVP_PKEY* diffieHellPrivateKey = NULL;
	unsigned char* nonceS = SecondHandShakeMessageHandler(sd, diffieHellPrivateKey, nonceC);

	if (nonceS == NULL) {
		return NULL;
	}

	std::cout << "=====================================================" << std::endl;
	std::cout << "2/3 HandShake messages are successful! Keep it up :) " << std::endl;
	std::cout << "=====================================================" << std::endl;


	// Third

	free(nonceS);

	return NULL;

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

	unsigned char* key = AuthenticateAndNegotiateKey(client);
	
	if (key==NULL) {
		std::cerr << "Authentication is still not completed! :|" << std::endl;
	}

	close(client);
	close(server);

	return 0;

}
