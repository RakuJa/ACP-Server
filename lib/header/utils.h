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

#define FAIL    -1


#define BUFFER  1024


#define NONCE_LEN 128
#define DH_KEY_LENGTH 128
#define USERNAME_MAX_LENGTH 17

typedef enum
{
    ERR_INVALID_OPID = 0xA0,
    ERR_INVALID_PAYLOAD_LEN,
    ERR_INVALID_PAYLOAD
} ErrorNum_t;

typedef enum
{
    OPID_ACK = 0,
    OPID_UPLOAD,
    OPID_DOWNLOAD,
    OPID_DELETE,
    OPID_LIST,
    OPID_RENAME,
    OPID_LOGOUT,
    OPID_DONE,
    OPID_ABORT,
    OPID_DATA,
    OPID_UNKWNOW = 0xFF
} operationID_t;



//SEND MESSAGE (PACCHETTI)

/*
Fetches the message to send from the given msg buffer and consumes until the given length, then sends to the given socket.
*/
int SendMessage(int socket, const void* msg, int length) {
    int result = 0;
    do {
        int tmp = send(socket, msg, length,0);
        if (tmp==-1) {
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
        return NULL;
    }
    result = recv(socket, msg, length, 0);
    if (result == -1) {
        free(msg);
        return msg;
    }
    while (result < length) {
        result += recv(socket, msg, length,0);
    }
    return msg;

}

/*
// READ MESSAGE
int ReadMessage(int socket, int *operationID, int *payloadlen, const void *buf, int buflength)
{
    operationID_t opid;

    // Read the operationID in order to deteermine how many chars to read
    int retvalue = 0;
    int payload_length = 0;
    char filename1[256];
    char filename2[256];
    unsigned long file_name_length2 = 0;
    unsigned long file_name_length1 = 0;
    unsigned long file_name_length = 0;

    retvalue = recv(socket, &opid, 1, 0);
    if (retvalue > 0)
    {
        int paylod_length = 0;
        switch (opid)
        {
        case OPID_ACK:
        case OPID_LIST:
        case OPID_DONE:
        case OPID_ABORT:
        case OPID_LOGOUT:
            // we already have all needed
            payload_length = 0;
            break;

        case OPID_UPLOAD:
        case OPID_DOWNLOAD:
        case OPID_DELETE:
            // next two-bytes are the lemgth of the filename
            unsigned long file_name_length1 = 0;
            retvalue = recv(socket, &file_name_length, 2, 0);
            if (retvalue != 2)
                return ERR_INVALID_PAYLOAD_LEN;

            if (file_name_length > 256)
                return ERR_INVALID_PAYLOAD_LEN;
            retvalue = recv(socket, filename1, file_name_length1, 0);
            if (retvalue != file_name_length)
                return ERR_INVALID_PAYLOAD;

            // return the filename as payload
            if (file_name_length1 <= buflength)
            {
                memcpy(buf, filename1, file_name_length1);
                *payloadlen = file_name_length1;
            }
            break;
        case OPID_RENAME:
            // next four bytes are the leght of the file names
            // totalbytes to be received is file_name_length1+file_name_length2+1
            file_name_length2 = 0;
            retvalue = recv(socket, &file_name_length, 4, 0);
            if (retvalue != 4)
                return ERR_INVALID_PAYLOAD_LEN;

            file_name_length1 = file_name_length && 0xFFFF;
            file_name_length2 = file_name_length >> 16;

            if ((file_name_length1 > 256) || (file_name_length2 > 256))
                return ERR_INVALID_PAYLOAD_LEN;

            retvalue = recv(socket, filename1, file_name_length1, 0);
            if (retvalue != file_name_length1)
                return ERR_INVALID_PAYLOAD;
            break;
            retvalue = recv(socket, filename2, file_name_length2, 0);
            if (retvalue != file_name_length1)
                return ERR_INVALID_PAYLOAD;

            // return the filenames separated by comma ',' as payload
            if ((file_name_length1 + 1 + file_name_length2) <= buflength)
            {
                memcpy(buf, filename1, file_name_length1);
                memset(buf + file_name_length1, 1, ',');
                memcpy(buf, filename2, file_name_length2);
                *payloadlen = file_name_length1 + 1 + file_name_length2;
            }
            break;

        case OPID_DATA:
            // next four bytes are the leght of the file names
            // totalbytes to be received is file_name_length1+file_name_length2+1
            payload_length = 0;
            unsigned char payload[0x10000];
            retvalue = recv(socket, &payload_length, 4, 0);
            if (retvalue != 4)
                return ERR_INVALID_PAYLOAD_LEN;

            retvalue = recv(socket, &payload[0], payload_length, 0);
            if (retvalue != payload_length)
                return ERR_INVALID_PAYLOAD;

            // return the filenames separated by comma ',' as payload
            if (payload_length <= buflength)
            {
                memcpy(buf, payload, payload_length);
                *payloadlen = payload_length;
            }
            break;

        default:
            return ERR_INVALID_OPID;
            break;
        }

        // save result to return
        *operationID = opid;
    }
} // SERGIO
*/

//GENERAZIONE NONCE/IV/RANDOM
int RandomGenerator(unsigned char* buf, int length) {
    // Seed OpenSSL PRNG
    RAND_poll();
    // Generate length bytes at random
    return RAND_bytes(buf, length);
} // ANDREA


//PARSE DELLE OPERAZIONE (IF OPERATIONID==1 THEN)
int ParseOperation(int operationID) {
    return 1;
    //etc
} // SERGIO

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
            if (!isalnum(*s)) return -1;
        return 1;
    }
    return -1;
}

/*
Removes all instances of the argument character from the argument string, then returns the modified string
*/
std::string RemoveCharacter(std::string input, char character) {
    input.erase(std::remove(input.begin(), input.end(),character), input.end());
    return input;
}