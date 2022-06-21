#ifndef UTILS_H
#define UTILS_H

#include <sys/socket.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <algorithm>
#include <fstream>
#include <openssl/err.h>
#include <string>
#include <vector>
#include <sstream>
#include "costants.h"

/*********************************************************
 *                                                       *
 *  _  _   ___   _____ __   __ ____   ____   _  _        *
 * ) \/ ( ) __( )__ __() (_) (/ __ \ /  _ \ ) |) /       *
 * |  \ | | _)    | |  \  _  /))__(( )  ' / | ( (        *
 * )_()_( )___(   )_(   )/ \( \____/ |_()_\ )_|)_\       *
 *                                                       *
 *                                                       *
 * *******************************************************/

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







//CANONIZZAZIONE INPUT (USERNAME, FILEPATH, FILENAME ETC)

/*
Removes all instances of the argument character from the argument string, then returns the modified string
*/
std::string RemoveCharacter(std::string input, char character) {
    input.erase(std::remove(input.begin(), input.end(),character), input.end());
    return input;
}

/*
Checks if the string is less than the maximum and if it does contain only alpha numeric.
Returns -1 if the string is not valid
*/
int ValidateString(std::string stringToAnalyze, int maxStringLength) {
    if (stringToAnalyze.length() <= USERNAME_MAX_LENGTH && !stringToAnalyze.empty()) {
        for (std::string::const_iterator s = stringToAnalyze.begin(); s != stringToAnalyze.end(); ++s)
            if (!isalnum(*s) && *s!='.') return FAIL;
        
        return (stringToAnalyze.at(0) != '.') == 0 ? FAIL : 1;
    }
    return FAIL;
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

void PrettyUpPrintToConsole(std:: string output) {
    std::cout << "========================" << std::endl;
    std::cout << output << std::endl;
    std::cout << "========================" << std::endl;
}

uint32_t GetFileSize(std::string filename) {
    struct stat stat_buf;
    return (stat(filename.c_str(), &stat_buf) == 0 && stat_buf.st_size < UINT32_MAX) ? stat_buf.st_size : 0;
}



#endif