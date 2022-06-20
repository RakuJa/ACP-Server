#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <openssl/x509.h>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

X509* ReadCertificate(const char*, const unsigned char*, uint32_t);

EVP_PKEY* ValidateCertificate(X509_STORE*, X509*);

X509_STORE* BuildStore(const char*,const char*);

#endif
