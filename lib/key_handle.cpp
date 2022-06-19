#include "../lib/header/key_handle.h"
#include <openssl/evp.h>
#include <openssl/pem.h>

/**
 * @brief generates a valid session key doing hash and then trunc using Kab as generator
 * 
 * @param hash_type Hash type to use for generating from Kab (generation = hash)
 * @param cypher_type Type of cypher
 * @param input Kab
 * @param input_length length of Kab
 * @param digest_length outoput length
 * @return unsigned* returns hashed Kab truncated to output length
 */
unsigned char* GenerateSessionKey(const EVP_MD* hash_type, const EVP_CIPHER* cypher_type, unsigned char* input, size_t input_length, unsigned int* digest_length) {
    unsigned char* full_key = ComputeHash(hash_type, input, input_length, digest_length);
    if (*digest_length > (unsigned int) EVP_CIPHER_key_length(cypher_type)) {
        unsigned char* truncated_key = (unsigned char*) malloc(EVP_CIPHER_key_length(cypher_type));
        if (truncated_key != NULL) {
            memcpy(truncated_key, full_key, EVP_CIPHER_key_length(cypher_type));
        }
        free(full_key);
        return truncated_key;
    }
    return full_key;
}

/**
 * @brief Generated Kab
 * 
 * @param my_prvkey Local private key
 * @param peer_pubkey Remote public key
 * @param secret_length length of secret
 * @return unsigned* values of Kab, REMEMBER TO DELETE
 */
unsigned char* GeneratePreSharedSecret(EVP_PKEY* myPrivateKey, EVP_PKEY* peerPublicKey, size_t secret_length) {
    /* Initializing shared secret derivation context */
    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(myPrivateKey, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv, peerPublicKey);
    EVP_PKEY_derive(ctx_drv, NULL, &secret_length);
    unsigned char* secret = new unsigned char[secret_length];
    EVP_PKEY_derive(ctx_drv, secret, &secret_length);
    EVP_PKEY_CTX_free(ctx_drv);
    return secret;
}


/**
 * @brief This method creates diffiehellman private and public key pair
 * 
 * @return EVP_PKEY* Generated diffiehellman key pair
 */
EVP_PKEY* GenerateDiffieHellmanPrivateAndPublicPair() {
    EVP_PKEY* dh_params = EVP_PKEY_new();
    if (EVP_PKEY_set1_DH(dh_params, DH_get_2048_224()) != 1) return NULL;

    EVP_PKEY_CTX* diffiehell_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    if (diffiehell_ctx == NULL) {
        EVP_PKEY_free(dh_params);
        return NULL;
    }

    if (EVP_PKEY_keygen_init(diffiehell_ctx) != 1) {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(diffiehell_ctx);
        return NULL;
    }

    EVP_PKEY* myPPKey = NULL;
    /*
    **Allocates memory for and generates a Diffie-Hellman private key
    **(which also contains the public key) and stores it in **pkey. 
    **Remember to free **pkey right after the key exchange!  Returns 1 on success.
    */
    int resultKeyGen = EVP_PKEY_keygen(diffiehell_ctx, &myPPKey); // & gets pointer to a pointer
    EVP_PKEY_CTX_free(diffiehell_ctx);
    EVP_PKEY_free(dh_params);
    
    return resultKeyGen == 1 ? myPPKey : NULL;
}

/**
 * @brief Exctract Public key from Private key, saves it to publicKey and saves its length to bufferLength. Returns unsigned char* value of public key
 * 
 * @param fileName Filename used for nothing important, --flavour--
 * @param myPPKey EVP_PKEY pointer that will be used to extract public key
 * @param publicKey publicKey Pointer to EVP_PKEY that will be overwritten with the value extracted from myPPKey
 * @return unsigned* unsigned char* value of the extracted public key
 */
unsigned char* ExtractPublicKey(const char* fileName, EVP_PKEY* myPPKey, uint32_t& publicKeyLength) {

    // Clean and initiate variables
    EVP_PKEY* publicKey = EVP_PKEY_new();
    uint32_t* bufferLength = new uint32_t[sizeof(u_int32_t)];

    // Convert from EVP_PKEY to PEM
    FILE* publicKeyPEM = fopen(fileName, "w+");
    if (publicKey == NULL || bufferLength == NULL || publicKeyPEM == NULL || PEM_write_PUBKEY(publicKeyPEM, myPPKey) != 1) {
        std::cerr<<"Error initializing conversion from private and public key pair to pem format" << std::endl;
        fclose(publicKeyPEM);
        return NULL;
    }
    

    // I really wanted to make two separate utility methods, one that would only read
    // EVP_PKEY publicKey and one that would convert the PEM to unsigned char* to send them
    // But it would only double the time i open the PEM file and even if i kept in memory it 
    // would only slow down or cause code duplication, very very sad.. sorry for the rant :C
    
    unsigned char* result = ConvertPublicKeyToCharsBuffer(publicKeyPEM, bufferLength);

    publicKey = PEM_read_PUBKEY(publicKeyPEM, NULL, NULL, NULL);

    fclose(publicKeyPEM);

    publicKeyLength = *bufferLength;
    
    return result;
}


EVP_PKEY* ConvertUnsignedCharToPublicDHKey(std::string filename, unsigned char* key, uint32_t& key_length) {

    FILE* pubkey_PEM = fopen(filename.c_str(),"w+");
    if(!pubkey_PEM){
        std::cout<<"Errore nell'apertura del file PEM\n";
        return NULL;
    }

    std::cout << "file aperto";
    
    //scrivo la chiave pubblica ricevuta nel file PEM
    uint32_t ret = fwrite(key,1,key_length,pubkey_PEM);
    if(ret < key_length){
        std::cout<<"Errore scrittura del file PEM\n";
        fclose(pubkey_PEM);
        return NULL;
    }

    fseek(pubkey_PEM,0,SEEK_SET);
    EVP_PKEY* received_pubkey = PEM_read_PUBKEY(pubkey_PEM,NULL,NULL,NULL);
    if(!received_pubkey){
        std::cout<<"Errore nella lettura della chiave pubblica ricevuta\n";
        fclose(pubkey_PEM);
        return NULL;
    }
    fclose(pubkey_PEM);
    return received_pubkey;
}


/**
 * @brief Converts PEM file to unsigned char*
 * 
 * @param keyPEM PEM file containing key to convert to resultBufferLength
 * @param resultBufferLength pointer that contains length of the extracted key
 * @return unsigned* extracted key
 */
unsigned char* ConvertPublicKeyToCharsBuffer(FILE* keyPEM, uint32_t* resultBufferLength) {

    // goes to the end of the file and gets the length, after this return at the beginning
    fseek(keyPEM, 0, SEEK_END);
    *resultBufferLength = (uint32_t)ftell(keyPEM);
    size_t resultBufferLengthSize = (size_t)* resultBufferLength; // UGh.. this name suck
    rewind(keyPEM);

    unsigned char* buffer = new unsigned char [resultBufferLengthSize];
    if (buffer == NULL) {
        std::cerr<<"Fatal error while reading the public key, malloc failed" << std::endl;
        return NULL;
    }

    // fread reads all the bytes if successful, so fread<fileLength only with an error
    if (fread(buffer, 1, resultBufferLengthSize, keyPEM) < resultBufferLengthSize) {//*resultBufferLength) {
        std::cerr<<"Error reading PEM file, runtime error." <<std::endl;
        fclose(keyPEM);
        free(buffer);
        return NULL;
    }
    
    rewind(keyPEM);

    return buffer;

}


/**
 * @brief loads private key from disk
 * 
 * @param filepath filepath where rsa private key is located, can be relative or absolute
 * @return EVP_PKEY* loaded private key
 */
EVP_PKEY* ReadRSAPrivateKey(const char* filepath){
    FILE* file = fopen(filepath,"r");
    if(!file) {
        return NULL;
    }
    EVP_PKEY* key = PEM_read_PrivateKey(file,NULL,NULL,NULL);
    fclose(file);
    return key;
}


/**
 * @brief loads public key from disk
 * 
 * @param filepath filepath where rsa public key is located, can be relative or absolute
 * @return EVP_PKEY* loaded public key
 */
EVP_PKEY* ReadRSAPublicKey(const char* filepath) {
    FILE* file = fopen(filepath, "r");
    if (!file) {
        return NULL;
    }
    EVP_PKEY* key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    return key;
}

std::string FromPublicKeyFileNameToPath(std::string filename) {
    std::string clientKeysFolder = "ClientsPubKey/";
    return clientKeysFolder + filename;
}



