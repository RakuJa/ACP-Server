<div align="center">
  <h1>Project ACCS 🚀 </h1>
</div>

<div align="center">

TCP secure server for Applied Cryptography course at UniPI 2021/2022.

[![Contributors][contributors-badge]][contributors]
[![Activity][activity-badge]][activity]
[![License][license-badge]](COPYING)

</div>

The students must implement a Client-Server application that resembles a Cloud Storage.
Each user has a “dedicated storage” on the server, and User A cannot access User B “dedicated storage”.
Users can Upload, Download, Rename, or Delete data to/from the Cloud Storage in a safe manner.
This software is tested and developed on Ubuntu 18.04.


## Project Specification

### Pre-Shared Crypto Material

Users:

* They have already the CA certificate;
* They have each a long-term RSA key-pair;
* The long-term private key is password-protected.

Server:

* It has its own certificate signed by the CA;
* It knows the username of every registered user;
* It knows the RSA public key of every user;
* “Dedicated Storage” already allocated.

### Requisites

* Users are pre-registered on the server. (so no registration or login function will be present);
* When the client application starts, Server and Client must authenticate:
- Server must authenticate with the public key certified by the certification authority;
- Client must authenticate with the public key, pre-shared with the server.
* During authentication a symmetric session key must be negotiated:
- The negotiation must provide Perfect Forward Secrecy;
- The entire session must be encrypted and authenticated;
- The entire session must be protected against replay attacks.

### Operations

Once connected to the server, the client can:

* **Upload**: Specifies a filename on the client machine and sends it to the server. The server saves the uploaded file with the filename specified by the user. If this is not possible, the file is not uploaded. **The uploaded file size can be up to 4GB**;
* **Download**: Specifies a file on the server machine. The server sends the requested file to the user. The filename of any downloaded file must be the filename used to store the file on the server. If this is not possible, the file is not downloaded;
* **Delete**: Specifies a file on the server machine. The server asks the user for confirmation. If the user confirms, the file is deleted from the server;
* **List**: The client asks to the server the list of the filenames of the available files in his dedicated storage. The client prints to screen the list;
* **Rename**: Specifies a file on the server machine. Within the request, the clients sends the new filename. If the renaming operation is not possible, the filename is not changed;
* **Logout**: The client gracefully closes the connection with the server.

### General Guidelines

* Use C or C++ language, and OpenSSL library for crypto algorithms;
* Key establishment protocol must establish one (or more) symmetric session key(s) with public-key crypto;
* Then, session protocol must use session key(s) to communicate;
* Communication must be confidential, authenticated, and protected against replay;
* No coding vulnerabilities (use secure coding principles, in particular CANONICALIZATION/INJECTION);
* Manage malformed messages.

## Service installation and startup 🏁
When a release will be published you will find the executable there, once downloaded execute the following commands:

### Server
./server 25565

### Client
./client 127.0.0.1 25565


## Project setup ⚙️🔧

To develop this project you will need to configure a proper enviroment.

download the project from the repository:

```bash
git clone 'https://github.com/RakuJa/Project_ACCS'
```

### Instructions for Ubuntu 18.04

#### Create Certs

I used xca to handle this process but you can use whatever you fancy. This tutorial will work only with xca ;) .

```bash
sudo apt update
sudo apt install xca
xca
```
Now you should have a good looking GUI ready to be used.

* Create a xca db;
* Create one private key for every user, one for the ROOT_CA and one for the Server (Remember to change keysize as needed);
* Generate CA Root:
- On Source select SHA 256 as Signature algorithm;
- Populate Subject accordingly and choose the ROOT_CA private key;
- On Extensions choose type Certificate Authority;
- On Key Usage choose Digital Signature, Certificate Sign and CRL Sign;
- Generate Server Certificate.
* Create a Certificate signing request:
- On Source select SHA 256 as Signature algorithm;
- Populate Subject accordingly and choose the Server key;
- On Extensions choose End Entity;
- On Key Usage choose Digital Signature, Key Agreement.
* Sign the Server Certificate using CA Root;
* Go to Revocation Lists and press "New CRL" (be carefull at the default expiration);
* Export the CRL as PEM and save it in "/Client/";
* Export all the users private key as PEM Encrypted and save them in "/Client/NameOfUser" with NameOfUser the name of the current user that will use that key;
* Export all the users public key as PEM public and save them in "/Server/ClientsPubKey";
* Export CA Root certificate as PEM and save it in "/Client/";
* Export Server certificate as PEM and save it in "/Server/".



**Install OpenSLL!**

You should now be ready to develop, if you are using VSCode I'm truly sorry for you, I had to use it and I still hate it.

## Compile from source

#### Server
```bash
g++ -Wall server.cpp ../lib/certificate.cpp ../lib/hash.cpp ../lib/key_handle.cpp -o server -lcrypto
```
#### Client
```bash
g++ client.cpp ../lib/certificate.cpp ../lib/hash.cpp ../lib/key_handle.cpp -o client -lcrypto
```
## CI and Tests 🤖

Pray



[contributors-badge]: https://img.shields.io/github/contributors/RakuJa/Project_ACCS "Contributors"

[contributors]: https://github.com/RakuJa/Project_ACCS/graphs/contributors "Contributors"

[activity-badge]: https://img.shields.io/github/commit-activity/m/RakuJa/Project_ACCS "Activity"

[activity]: https://github.com/RakuJa/Project_ACCS/pulse "Activity"

[license-badge]: https://img.shields.io/github/license/RakuJa/Project_ACCS
