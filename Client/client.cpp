// Daniele Giachetto - Foundation of Cybersecurity Project



#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../lib/header/utils.h"
#include "../lib/header/hash.h"


void CloseAfterFirstPacketFailure(int sd, unsigned char* nonce_buf) {
	close(sd);
	free(nonce_buf);
	exit(1);
}

unsigned char* AuthenticateAndNegotiateKey(int sd) {
	
	// Nonce(c) generation
	unsigned char* nonce_buf = (unsigned char*)malloc(NONCE_LEN);
	if (nonce_buf == NULL || RandomGenerator(nonce_buf, NONCE_LEN) == -1) {
		std::cout<<"Could not generate nonce(c) \n";
		CloseAfterFirstPacketFailure(sd, nonce_buf);
	}
	// Get username
	std::string username;
	do {
		printf("Please insert a valid username (only alphanumeric character and length < %d : \n", USERNAME_MAX_LENGTH);
		std::cin>>username;
	} while (std::cin.fail() || parse_string(username) != 1);
	username.resize(USERNAME_MAX_LENGTH); // add padding to standardize packet size

	// Send first packet, nonce(c) and username
	if (SendMessage(sd, username.c_str(), USERNAME_MAX_LENGTH) == -1 || SendMessage(sd, nonce_buf, NONCE_LEN) == -1) {
		std::cout<<"Error sending username and nonce(c) \n";
		CloseAfterFirstPacketFailure(sd, nonce_buf);
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

	if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) == -1 )
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
