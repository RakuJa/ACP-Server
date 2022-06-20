#ifndef UTILS_H
#define UTILS_H

#include <sys/socket.h>
#include <openssl/rand.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <algorithm>
#include <fstream>
#include <openssl/err.h>

#define FAIL    -1

#define HANDSHAKE_ERROR "0"
#define HANDSHAKE_ACK "1"

#define SERVER_CERT_NAME "ServerCert.pem"

#define NONCE_LEN 16
#define DH_KEY_LENGTH 16
#define USERNAME_MAX_LENGTH 17
#define IV_LENGTH 12
#define AAD_LENGTH 28
#define TAG_LENGTH 16

//SEND MESSAGE (PACCHETTI)

/*
Fetches the message to send from the given msg buffer and consumes until the given length, then sends to the given socket.
*/
int SendMessage(int socket, const void* msg, u_int32_t length) {
    u_int32_t result = 0;
    int tmp = 0;
    do {
        tmp = send(socket, msg, length, 0);
        if (tmp==FAIL) {
            return tmp;
        }
        result += tmp;
    } while (result < length);
    std::cout<<"Sent " << result << " bytes out of " << length << "\n";
    return result;
}


/*
Reads length bytes from the socket and returns them
*/
template<class T>
int ReadMessage(int socket, u_int32_t length, T** outBuffer) {

    // READ CONTENT FROM SOCKET

    u_int32_t result = 0;
    T* msg = new T[length];

    int tmp = 0;
    do {
        tmp = recv(socket, msg, length, 0);
        if (tmp == FAIL) {
            delete[] msg;
            return FAIL;
        }
        result +=tmp;
    } while (result < length);
    std::cout <<"Received " << result << " bytes out of " << length << "\n";
    *outBuffer = msg;
    return 1;

}


//GENERAZIONE NONCE/IV/RANDOM
int RandomGenerator(unsigned char* &buf,unsigned int length) {
    // Seed OpenSSL PRNG
    RAND_poll();
    // Generate length bytes at random
    return RAND_bytes(buf, length);
} 

//CANONIZZAZIONE INPUT (USERNAME, FILEPATH, FILENAME ETC)


/*
Checks if the string is less than the maximum and if it does contain only alpha numeric.
Returns -1 if the string is not valid
*/
int ParseString(std::string analyze_string) {
    if (analyze_string.length() <= USERNAME_MAX_LENGTH) {
        for (std::string::const_iterator s = analyze_string.begin(); s != analyze_string.end(); ++s)
            if (!isalnum(*s)) return FAIL;
        return 1;
    }
    return FAIL;
}

/*
Removes all instances of the argument character from the argument string, then returns the modified string
*/
std::string RemoveCharacter(std::string input, char character) {
    input.erase(std::remove(input.begin(), input.end(),character), input.end());
    return input;
}

std::string ReadFile(const std::string &filename) {
    std::ifstream file(filename);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}


void PrintListOfOperations() {
    std::cout << "========================" << std::endl;
    std::cout << "(0) Help" << std::endl;
    std::cout << "(1) Upload" << std::endl;
    std::cout << "(2) Download" << std::endl;
    std::cout << "(3) Delete" << std::endl;
    std::cout << "(4) List" << std::endl;
    std::cout << "(5) Rename" << std::endl;
    std::cout << "(6) Logout" << std::endl;
    std::cout << "========================" << std::endl;
    std::cout << std::endl << "Insert the corresponding number to execute the desired operation:" << std::endl;
}



#endif