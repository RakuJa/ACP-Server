// Daniele Giachetto - Foundation of Cybersecurity Project


#include <unistd.h>
#include <malloc.h>
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

int CloseConnection() {
	return 1;
}

// Root User Check
int isRoot()
{
	if (getuid() != 0)
		return 0;
	else
		return 1;
}

unsigned char* AuthenticateAndNegotiateKey(int sd) {

	/***********************
	**GET USERNAME & NONCE**
	***********************/

	unsigned char* username = ReadMessage(sd, USERNAME_MAX_LENGTH);

	std::string sName = ConvertFromUnsignedCharToString(username, USERNAME_MAX_LENGTH);
	sName = RemoveCharacter(sName, ' ');
	sName = RemoveCharacter(sName, '\0');
	std::cout<<sName<< '\n';

	if (parse_string(sName) == -1) {
		std::cout<<"Fallita la validazione dello username: " << sName << '\n';
		SendMessage(sd, HANDSHAKE_ERROR, sizeof(HANDSHAKE_ERROR));
		exit(1);
	}
	unsigned char* nonceC = ReadMessage(sd, NONCE_LEN);

	// Send ack or abort
	SendMessage(sd, HANDSHAKE_ACK, sizeof(HANDSHAKE_ACK));

	/***************************************
	**READ CERTIFICATE FROM DISK & SEND IT**
	****************************************/

	std::string serverCer = ReadFile(SERVER_CERT_NAME);
	// std::cout<< "Certificate length " <<std::to_string(serverCer.length()).c_str() << '\n';

	// send cert length
	SendMessage(sd, std::to_string(serverCer.length()).c_str(), sizeof(uint32_t));

	// send cert
	SendMessage(sd, serverCer.c_str(), serverCer.length());

	unsigned char resultOfLogin = *ReadMessage(sd, sizeof(HANDSHAKE_ERROR));
	std::cout<<resultOfLogin << '\n';
	if (resultOfLogin == *HANDSHAKE_ERROR) {
		std::cerr << "Certificate was not valid for the client" << '\n';
		exit(1);
	}

	EVP_PKEY* myPrivateKey = GenerateDiffieHellmanPrivateAndPublicPair();
	if (myPrivateKey == NULL) {
		std::cerr << "Error generating private key, u fucked up kiddo" << std::endl;
		exit(1);
	}

	EVP_PKEY* myPublicKey = NULL;
	unsigned char* serverPublicKey = ExtractPublicKey("ServerDhPublicKey.PEM", myPrivateKey, myPublicKey);

	if (serverPublicKey == NULL) {
		std::cerr << "Error generating public key, u fucked up kiddo" << std::endl;
		exit(1);
	}
	u_int32_t serverPublicKeyLength = sizeof(serverPublicKey);

	if (SendMessage(sd, std::to_string(serverPublicKeyLength).c_str(), sizeof(uint32_t)) == FAIL) {
		std::cerr << "Error sending public key length" << std::endl;
	}

	if (SendMessage(sd, serverPublicKey, serverPublicKeyLength) == FAIL) {
		std::cerr << "Error sending public key" << std::endl;
	} 

	/***************************
	**GENERATE NONCE & SEND IT**
	***************************/

	// Nonce(s) generation
	unsigned char* nonceS = (unsigned char*)malloc(NONCE_LEN);
	if (nonceS == NULL || RandomGenerator(nonceS, NONCE_LEN) == FAIL) {
		std::cerr<<"Could not generate nonce(s) \n";
	}

	
	if (SendMessage(sd, nonceS, NONCE_LEN) == FAIL) {
		std::cerr<<"Failure while sending nonce(s)";
	}


	unsigned char* msgToSign = (unsigned char*) malloc (NONCE_LEN + serverPublicKeyLength);
	if (msgToSign == NULL) {
		std::cerr << "Failure allocating memory for signing" << std::endl;
	}

	memcpy(msgToSign, nonceC, NONCE_LEN);
	memcpy(msgToSign + NONCE_LEN, serverPublicKey, serverPublicKeyLength);
	//free(serverPublicKey);
	free(nonceC);

	uint32_t* signatureLength = (uint32_t*) malloc(sizeof(uint32_t));
	if (signatureLength == NULL) {
		std::cerr << "Error allocating signature length space" << std::endl;
	}

	// READS SERVER PRIVATE KEY

	EVP_PKEY* serverRSAPrivateKey = ReadRSAPrivateKey("ServerRSAPrivate.pem");

	if (serverRSAPrivateKey == NULL) {
		std::cerr << "Error loading server private key from disk" << std::endl;
	}

	unsigned char* msgSigned = ComputeSign(EVP_sha256(), msgToSign, NONCE_LEN+serverPublicKeyLength, signatureLength, serverRSAPrivateKey);
	
	if (SendMessage(sd, std::to_string(*signatureLength).c_str(), sizeof(uint32_t)) == FAIL) {
		std::cerr << "error sending sign size" << std::endl;
	}

	if (SendMessage(sd, msgSigned, *signatureLength) == FAIL) {
		std::cerr << "Error sending signature" << std::endl;
	}

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


		const char* banner = R"(
   ___  _____    ___  ___  ____     _________________
  / _ |/ ___/   / _ \/ _ \/ __ \__ / / __/ ___/_  __/
 / __ / /__    / ___/ , _/ /_/ / // / _// /__  / /   
/_/ |_\___/   /_/  /_/|_|\____/\___/___/\___/ /_/    
     / __/__ _____  _____ ____                       
    _\ \/ -_) __/ |/ / -_) __/                       
   /___/\__/_/  |___/\__/_/                          
                                                     
	)";
	std::cout<<banner << "\n";



	listen(server,5);

	int client = accept(server, (struct sockaddr*)&addr, &len);

	printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

	unsigned char* key = AuthenticateAndNegotiateKey(client);
	//std::cout<<key;

	close(client);
	close(server);

	return 0;

}
