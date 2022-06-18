// Daniele Giachetto - Foundation of Cybersecurity Project



#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../lib/header/utils.h"
#include "../lib/header/hash.h"
#include "../lib/header/certificate.h"


void CloseAfterFirstPacketFailure(int sd, unsigned char* nonce_buf) {
	close(sd);
	free(nonce_buf);
	exit(1);
}

/**
 * @brief Sends the login message to the server, returns NULL if nonce failed to generate or username was refused by the server
 * 
 * @param usernamename will be used to return the username that succeded login
 * @return unsigned* the generated nonce sent to the server
 */
unsigned char* FirstHandShakeMessageHandler(int sd, std::string & username) {
	
	//                FIRST MESSAGE                //
	/************************************************
	**GENERATE NONCE, GET USERNAME & SEND THEM BOTH**
	*************************************************/


	unsigned char* nonceC = (unsigned char*)malloc(NONCE_LEN);
	if (nonceC == NULL || RandomGenerator(nonceC, NONCE_LEN) == FAIL) {
		std::cerr<<"Could not generate nonce(c)" << std::endl;
		CloseAfterFirstPacketFailure(sd, nonceC);
	}
	// Get username
	do {
		printf("Please insert a valid username (only alphanumeric character and length < %d : \n", USERNAME_MAX_LENGTH);
		std::cin>>username;
	} while (std::cin.fail() || parse_string(username) != 1);
	username.resize(USERNAME_MAX_LENGTH); // add padding to standardize username length and avoid sending a message with username size


	// Send first packet, nonce(c) and username
	if (SendMessage(sd, username.c_str(), USERNAME_MAX_LENGTH) == FAIL || SendMessage(sd, nonceC, NONCE_LEN) == FAIL) {
		std::cerr<<"Error sending username and nonce(c)" << std::endl;
		CloseAfterFirstPacketFailure(sd, nonceC);
	}

	unsigned char resultOfLogin = *ReadMessage(sd, sizeof(HANDSHAKE_ERROR));
	if (resultOfLogin == *HANDSHAKE_ERROR) {
		std::cerr << "Username was not valid for the server" << std::endl;
		CloseAfterFirstPacketFailure(sd, nonceC);
	}

	std::cout << "Username " << username << " is valid, login success!" << std::endl;
	return nonceC;
}

/**
 * @brief Receives the login response from the server, that contains server certificate, nonce(s), sign(nonce(c), A), A(preshared secret)
 * in case of error somewhere down the line returns NULL and handles all the frees (except the passed arguments) inside the method
 * 
 * @param sd socket to receive and send messages from
 * @param serverDhPublicKey will be used to return the pre-shared secret A (also called publicDHKey or peerDHKey)
 * @param nonceC nonce sent previously to the server, used in the method to verify sign(nonce(c), A)
 * @return unsigned* the nonce sent by the server
 */
unsigned char* SecondHandShakeMessageHandler(int sd, unsigned char* serverDhPublicKey, unsigned char* nonceC) {
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
	int certificateBytesLength = stoi(ConvertFromUnsignedCharToString(ReadMessage(sd, sizeof(u_int32_t)), sizeof(u_int32_t)));
	if (certificateBytesLength == 0 || certificateBytesLength == -1) {
		std::cerr << "Certificate length received is invalid" << std::endl;
		return NULL;
	}

	// GETS CERTIFICATE
	unsigned char* serverCertificate = ReadMessage(sd, certificateBytesLength);

	if (serverCertificate == NULL) {
		std::cerr << "Certificate read failed" << std::endl;
		return NULL;
	}

	// PARSE AND VALIDATE CERTIFICATE
	X509* parsedServerCertificate = ReadCertificate(SERVER_CERT_NAME, serverCertificate, certificateBytesLength);
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

	// GET A (PRESHARED SECRET) LENGTH


	int serverDhPublicKeyLength = stoi(ConvertFromUnsignedCharToString(ReadMessage(sd, sizeof(u_int32_t)), sizeof(u_int32_t)));

	if (serverDhPublicKeyLength == 0 || serverDhPublicKeyLength == -1) {
		std::cerr << "DiffieHellman public key length received is invalid" << std::endl;
		return NULL;
	}

	// GET A (PRESHARED SECRET)
	serverDhPublicKey = ReadMessage(sd, serverDhPublicKeyLength);

	// READ SIGNATURE

	int serverSignLength = stoi(ConvertFromUnsignedCharToString(ReadMessage(sd, sizeof(u_int32_t)), sizeof(u_int32_t)));
	if (serverSignLength == 0 || serverSignLength == -1) {
		std::cerr << "Server signature length received is invalid" << std::endl;
	}

	unsigned char* serverSign = ReadMessage(sd, serverSignLength);


	// Sign (NONCE(C) + A)
	
	int msgToSignLength = NONCE_LEN + serverDhPublicKeyLength;

	std::basic_string<unsigned char> part1 = nonceC;
	std::basic_string<unsigned char> part2 = serverDhPublicKey;
	std::basic_string<unsigned char> msgToSign = part1 + part2;

	if (VerifySign(EVP_sha256(), serverSign, serverSignLength, msgToSign.c_str(), msgToSign.length(), serverRSAPubKey) != 1) {
		std::cerr << "Could not verify sign(nonce(c), A)! Closing connection..." << std::endl;
		SendMessage(sd, HANDSHAKE_ERROR, sizeof(HANDSHAKE_ERROR));
		return NULL;
	}

	SendMessage(sd, HANDSHAKE_ACK, sizeof(HANDSHAKE_ACK));

	EVP_PKEY_free(serverRSAPubKey);

	// GETS NONCE(S)
	unsigned char* nonceS = ReadMessage(sd, NONCE_LEN);

	return nonceS;
}

unsigned char* AuthenticateAndNegotiateKey(int sd) {
	
	std::string username = "Kurisu Makise";

	unsigned char* nonceC = FirstHandShakeMessageHandler(sd, username);

	if (nonceC == NULL) {
		return NULL;
	}
	std::cout << "=====================================================" << std::endl;
	std::cout << "1/3 HandShake messages are successful! Keep it up :) " << std::endl;
	std::cout << "=====================================================" << std::endl;

	unsigned char* diffieHellPublicKey = NULL;

	unsigned char* nonceS = SecondHandShakeMessageHandler(sd, diffieHellPublicKey, nonceC);
	if (nonceS == NULL) {
		CloseAfterFirstPacketFailure(sd, nonceC);
	}

	free(nonceC);

	std::cout << "=====================================================" << std::endl;
	std::cout << "2/3 HandShake messages are successful! Keep it up :) " << std::endl;
	std::cout << "=====================================================" << std::endl;
	
	
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
	unsigned char* x = AuthenticateAndNegotiateKey(sd);
	if (x == NULL) {
		close(sd);
	}


	/*************************
	** LOGIN SUCCESS ART :) **
	**************************/

	std::string handshakeSuccessFile = "login_success_art.txt";
	std::cout<<ReadFile(handshakeSuccessFile) << std::endl;

	
	return 0;
}
