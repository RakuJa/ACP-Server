#include "header/certificate.h"



X509* ReadCertificate(char* fileName, unsigned char* buffer, uint32_t length) {

    // Read buffer into File
    FILE* f_cert = fopen(fileName,"w+");
    if(!f_cert) return NULL;
    // Calcola il minimo divisore e mettilo al posto di 1 e al posto di length metto length/minimo divisore
    fwrite(buffer,1,length,f_cert);
    rewind(f_cert);

    X509* cert = PEM_read_X509(f_cert,NULL,NULL,NULL);
    fclose(f_cert);
    return cert;
}


X509_STORE* BuildStore(char* file_crl,char* root_cert){
    X509_STORE* store = X509_STORE_new();
    if(!store) {
        std::cerr<<"Error: X509_STORE_new returned NULL" << std::endl;
        return NULL;
    }
    FILE* f_crl = fopen(file_crl,"r");
    if(!f_crl) {
        return NULL;
    }
    X509_CRL* crl = PEM_read_X509_CRL(f_crl,NULL,NULL,NULL);
    if(!crl) {
        return NULL;
    }
    fclose(f_crl);
    FILE* f_root = fopen(root_cert,"r");
    if(!f_root) {
        return NULL;
    }
    X509* root = PEM_read_X509(f_root,NULL,NULL,NULL);
    if(!root) {
        return NULL;
    }
    fclose(f_root);

    if(!X509_STORE_add_cert(store,root)) return NULL;
    if(!X509_STORE_add_crl(store,crl)) return NULL;
    if(!X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK)) return NULL;
    
    return store;
}

EVP_PKEY* ValidateCertificate(X509_STORE* store, X509* cert){

    if(!X509_STORE_add_cert(store,cert)) return NULL;
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if(!ctx) return NULL;
    if(!X509_STORE_CTX_init(ctx, store, cert, NULL)){
        X509_STORE_CTX_free(ctx);
        return NULL;
    }
    if(X509_verify_cert(ctx) == 1){
        X509_STORE_CTX_free(ctx);
        if(std::string(X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0)).find("O=El Psy Kongroo") == std::string::npos){
            std::cerr<<"Given certificate is not the server one" << std::endl;
            return NULL;
        }                                                                              
        return X509_get_pubkey(cert);
    }
    else
        std::cerr<<X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)) << std::endl;
    X509_STORE_CTX_free(ctx);
    return NULL;
} 