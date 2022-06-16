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
		perror("PORT BINDING ERROR");
		abort();
	}

	if ( listen(sd, 10) != 0 )
	{
		perror("LISTENING PORT CONFIGURATION PROBLEM");
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
	unsigned char* username = ReadMessage(sd, USERNAME_MAX_LENGTH);

	//username[USERNAME_MAX_LENGTH-1] = '\0';

	std::string sName (reinterpret_cast<char*>(username), USERNAME_MAX_LENGTH);
	sName = RemoveCharacter(sName, ' ');
	sName = RemoveCharacter(sName, '\0');
	std::cout<<sName<< '\n';

	if (parse_string(sName) == -1) {
		std::cout<<"Fallita la validazione dello username: " << sName << '\n';
		return username;
	}
	unsigned char* nonce = ReadMessage(sd, NONCE_LEN);
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
