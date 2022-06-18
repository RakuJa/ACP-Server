#include <sys/socket.h>
#include <openssl/rand.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <algorithm>
#include <fstream>
#include <openssl/err.h>

#define FAIL    -1
#define BUFFER  1024
#define NONCE_LEN 16
#define HANDSHAKE_ERROR "0"
#define HANDSHAKE_ACK "1"
#define DH_KEY_LENGTH 16
#define USERNAME_MAX_LENGTH 17
#define SERVER_CERT_NAME "ServerCert.pem"

//SEND MESSAGE (PACCHETTI)

/*
Fetches the message to send from the given msg buffer and consumes until the given length, then sends to the given socket.
*/
int SendMessage(int socket, const void* msg, int length) {
    int result = 0;
    do {
        int tmp = send(socket, msg, length, 0);
        if (tmp==FAIL) {
            return tmp;
        }
        result += tmp;
    } while (result < length);
    std::cout<<"Sent " << result << "bytes out of " << length << "\n";
    return result;
}

/*
Reads length bytes from the socket and returns them
*/
unsigned char* ReadMessage(int socket, int length) {
    int result = 0;
    unsigned char* msg = (unsigned char*)malloc(length);

    if (msg==NULL) {
        std::cerr << "Failed to allocate memory to read message" << std::endl;
        return NULL;
    }

    do {
        int tmp = recv(socket, msg, length, 0);
        if (tmp == FAIL) {
            free(msg);
            return NULL;
        }
        result +=tmp;
    } while (result < length);
    std::cout<<"Received " << result << "bytes out of " << length << "\n";
    return msg;

}

//GENERAZIONE NONCE/IV/RANDOM
int RandomGenerator(unsigned char* &buf, int length) {
    // Seed OpenSSL PRNG
    RAND_poll();
    // Generate length bytes at random
    return RAND_bytes(buf, length);
} 


//CRIPTAZIONE DEI PACCHETTI


//DECRIPTAZIONE DEI PACCHETTI


//CANONIZZAZIONE INPUT (USERNAME, FILEPATH, FILENAME ETC)


/*
Checks if the string is less than the maximum and if it does contain only alpha numeric.
Returns -1 if the string is not valid
*/
int parse_string(std::string analyze_string) {
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

std::string ConvertFromUnsignedCharToString(const unsigned char* input, uint length) {
    return std::string(reinterpret_cast<const char*>(input), length);
}

const char* ConvertFromUnsignedCharToSigned(const unsigned char* input) {
    return reinterpret_cast<const char*>(input);
}