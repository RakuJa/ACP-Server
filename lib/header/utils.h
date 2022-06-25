#ifndef UTILS_H
#define UTILS_H


#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <fstream>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <dirent.h>

#include "costants.h"
#include "operation_package.h"


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
    std::cout << "============================" << std::endl;
    std::cout << "(0) Help" << std::endl;
    std::cout << "(1) Upload" << std::endl;
    std::cout << "(2) Download" << std::endl;
    std::cout << "(3) Delete" << std::endl;
    std::cout << "(4) List" << std::endl;
    std::cout << "(5) Rename" << std::endl;
    std::cout << "(6) Logout" << std::endl;
    std::cout << "============================" << std::endl;
    std::cout << std::endl << "Insert the corresponding number to execute the desired operation:" << std::endl;
}

void PrettyUpPrintToConsole(std:: string output) {
    std::string border = std::string(strlen(output.c_str()), '=');
    std::cout << border << std::endl;
    std::cout << output << std::endl;
    std::cout << border << std::endl;
}


int CheckFileExistance(std::string filename) {
	FILE* fileToCheck = fopen(filename.c_str(), "r");
	if (fileToCheck == NULL) {
		return FAIL;
	}
    fclose(fileToCheck);
    return 1;
}

uint32_t GetFileSize(std::string filename) {
    struct stat stat_buf;
    return (stat(filename.c_str(), &stat_buf) == 0 && stat_buf.st_size < UINT32_MAX) ? stat_buf.st_size : 0;
}



uint32_t GetNumberOfDataBlocks(uint64_t fileSize){
    return fileSize/PAYLOAD_BUFFER_MAX_SIZE + (fileSize % PAYLOAD_BUFFER_MAX_SIZE != 0);
}

int ClearBufferArea(unsigned char* buff, int buffLength) {
    memset(buff, 0, buffLength);
    delete[] buff;
    return 1;
}


std::string GetUserStoragePath(std::string username, const char* inputFilename) {
    username = RemoveCharacter(username, '\0');
    std::string storage = "Storage/";
    std::string completeFilename = inputFilename!=NULL? storage + username + '/' + inputFilename : storage + username + '/';
    return completeFilename;
}


std::vector<std::string> GetFilesInDirectory(DIR* directory) {
    std::vector<std::string> listOfFiles;
    std::string currEntry;
    struct dirent *ent; //THX stackoverflow
    if (directory != NULL) {
        while((ent = readdir(directory))!=NULL) {
            currEntry = ent->d_name;
            if (ValidateString(currEntry, FILENAME_LENGTH) !=FAIL) listOfFiles.push_back(currEntry);
        }
    }
    return listOfFiles;
}

std::string ConcatenateFileNames(std::vector<std::string> fileVector, std::string separator) {
    std::string concatResult;
    //TODO GOD I HATE THIS :PUKE:
    bool first = 1;
    std::string cleanEntry;
    for (const auto & entry: fileVector) {
        cleanEntry = RemoveCharacter(entry, '\0');
        if (ValidateString(cleanEntry, FILENAME_LENGTH) == 1) {
            if (first != 1) {
                concatResult.append(separator);
            }
            first = 0;
            concatResult.append(cleanEntry);
        }
    }
    return concatResult;
}

std::vector<std::string> SplitBufferByCharacter(char* buffer, uint64_t bufferLength, char splitSeparator) {

    std::vector<std::string> fileList;
    if (buffer!=NULL) {
        std::string toSplit (buffer, bufferLength);

        std::stringstream ss(toSplit);
        std::string currElement;

        while(std::getline(ss, currElement, splitSeparator)) {
            fileList.push_back(currElement);
        }
    }
    return fileList;
}

#endif