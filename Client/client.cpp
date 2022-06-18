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

unsigned char* AuthenticateAndNegotiateKey(int sd) {
	

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
	std::string username;
	do {
		printf("Please insert a valid username (only alphanumeric character and length < %d : \n", USERNAME_MAX_LENGTH);
		std::cin>>username;
	} while (std::cin.fail() || parse_string(username) != 1);
	username.resize(USERNAME_MAX_LENGTH); // add padding to standardize packet size


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

	std::cout << "Username " << username << "is valid, login success!" << std::endl;

	//                  SECOND MESSAGE                 //
	/***************************************************
	**GETS CERTIFICATE, A, NONCE(S), SIGN(NONCE(S), A)**
	***************************************************/

	/*
	* 1) GETS CERTIFICATE SIZE & CERTIFICATE
	* 2) PARSE AND VALIDATE CERTIFICATE
	* 3) GETS A
	* 4) GETS SIGN(A, NONCE(C))
	*/

	// GETS CERTIFICATE SIZE
	int certificateBytesLength = stoi(ConvertFromUnsignedCharToString(ReadMessage(sd, sizeof(u_int32_t)), sizeof(u_int32_t)));
	if (certificateBytesLength == 0 || certificateBytesLength == -1) {
		std::cerr << "Certificate length received is invalid" << std::endl;
		CloseAfterFirstPacketFailure(sd, nonceC);
	}

	// GETS CERTIFICATE
	unsigned char* serverCertificate = ReadMessage(sd, certificateBytesLength);

	if (serverCertificate == NULL) {
		std::cerr << "Certificate read failed" << std::endl;
		CloseAfterFirstPacketFailure(sd, nonceC);
	}

	// PARSE AND VALIDATE CERTIFICATE
	X509* parsedServerCertificate = ReadCertificate(SERVER_CERT_NAME, serverCertificate, certificateBytesLength);
	if (parsedServerCertificate == NULL) {
		std::cerr << "Error parsing server certificate" << std::endl;
	}
	X509_STORE* store = BuildStore("ClientCrl.pem", "ServerRoot.pem");
	if (store == NULL) {
		std::cerr << "Error building certificate store" << std::endl;
	}
	EVP_PKEY* serverRSAPubKey = ValidateCertificate(store, parsedServerCertificate);
	if (serverRSAPubKey == NULL) {
		std::cerr << "Server certificate is not valid" << std::endl;
		SendMessage(sd, HANDSHAKE_ERROR, sizeof(HANDSHAKE_ERROR));
		exit(1);
	}
	SendMessage(sd, HANDSHAKE_ACK, sizeof(HANDSHAKE_ACK));


	// GET A LENGTH

	int dhPublicKeyBytesLength = stoi(ConvertFromUnsignedCharToString(ReadMessage(sd, sizeof(u_int32_t)), sizeof(u_int32_t)));
	std::cout << "DiffieHellman public key byte size: " <<  dhPublicKeyBytesLength << std::endl;

	if (dhPublicKeyBytesLength == 0 || dhPublicKeyBytesLength == -1) {
		std::cerr << "DiffieHellman public key length received is invalid" << std::endl;
		CloseAfterFirstPacketFailure(sd, nonceC);
	}

	// GET A (PRESHARED SECRET)
	unsigned char* serverPublicKey = ReadMessage(sd, dhPublicKeyBytesLength);

	// GETS NONCE(S)
	unsigned char* nonceS = ReadMessage(sd, NONCE_LEN);

	int signLength = stoi(ConvertFromUnsignedCharToString(ReadMessage(sd, sizeof(u_int32_t)), sizeof(u_int32_t)));

	std::cout << signLength << std::endl;

	unsigned char* signedNonceAndPreShared = ReadMessage(sd, signLength);

	std::cout << signedNonceAndPreShared << std::endl;
	
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

	const char* banner = R"(
   ___  _____    ___  ___  ____     _________________  
  / _ |/ ___/   / _ \/ _ \/ __ \__ / / __/ ___/_  __/  
 / __ / /__    / ___/ , _/ /_/ / // / _// /__  / /     
/_/ |_\___/___/_/  /_/|_______/\___/___/\___/ /_/      
      ____/ (_)__ ___  / /_                            
     / __/ / / -_) _ \/ __/                            
     \__/_/_/\__/_//_/\__/                             
                                                                                                                          
	)";
	std::cout<<banner << "\n";
	AuthenticateAndNegotiateKey(sd);
	return 0;
}
