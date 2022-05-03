<div align="center">
  <h1>ACP-Server 🚀 </h1>
</div>

<div align="center">

TCP secure server for Applied cryptography course at UniPI 2021/2022 

[![Contributors][contributors-badge]][contributors]
[![Activity][activity-badge]][activity]
[![License][license-badge]](COPYING)

</div>

The students must implement a Client-Server application that resembles a Cloud Storage.
Each user has a “dedicated storage” on the server, and User A cannot access User B “dedicated storage”.
Users can Upload, Download, Rename, or Delete data to/from the Cloud Storage in a safe manner.
This software is tested and developed on Ubuntu 18.04


## Project Specification

### Pre-Shared Crypto Material

Users:

* They have already the CA certificate.
* They have each a long-term RSA key-pair.
* The long-term private key is password-protected.

Server:

* It has its own certificate signed by the CA.
* It knows the username of every registered user.
* It knows the RSA public key of every user.
* “Dedicated Storage” already allocated.

### Requisites

* Users are pre-registered on the server. (so no registration or login function will be present)
* When the client application starts, Server and Client must authenticate.
- Server must authenticate with the public key certified by the certification authority.
- Client must authenticate with the public key, pre-shared with the server.
* During authentication a symmetric session key must be negotiated.
- The negotiation must provide Perfect Forward Secrecy.
- The entire session must be encrypted and authenticated.
- The entire session must be protected against replay attacks.

### Operations

Once connected to the server, the client can:

* **Upload**: Specifies a filename on the client machine and sends it to the server. The server saves the uploaded file with the filename specified by the user. If this is not possible, the file is not uploaded. **The uploaded file size can be up to 4GB**
* **Download**: Specifies a file on the server machine. The server sends the requested file to the user. The filename of any downloaded file must be the filename used to store the file on the server. If this is not possible, the file is not downloaded.
* **Delete**: Specifies a file on the server machine. The server asks the user for confirmation. If the user confirms, the file is deleted from the server.
* **List**: The client asks to the server the list of the filenames of the available files in his dedicated storage. The client prints to screen the list.
* **Rename**: Specifies a file on the server machine. Within the request, the clients sends the new filename. If the renaming operation is not possible, the filename is not changed.
* **Logout**: The client gracefully closes the connection with the server.

### General Guidelines

* Use C or C++ language, and OpenSSL library for crypto algorithms.
* Key establishment protocol must establish one (or more) symmetric session key(s) with public-key crypto.
* Then, session protocol must use session key(s) to communicate.
* Communication must be confidential, authenticated, and protected against replay.
* No coding vulnerabilities (use secure coding principles, in particular CANONICALIZATION/INJECTION)
* Manage malformed messages

## Service installation and startup 🏁
When a release will be published you will find the executable there, once downloaded execute the following commands:

```bash
chmod +x
./ACP-Server
```

## Project setup ⚙️🔧

To develop this project you will need to configure a proper enviroment.

download the project from the repository:

```bash
git clone 'https://github.com/RakuJa/ACP-Server'
```

### Instructions for Ubuntu 18.04

Download QT dependencies 

#### Optional

QT Documentation 
```bash
sudo apt install qt5-doc qt5-doc-html qtbase5-doc-html qtbase5-examples
```

QtCreator as IDE:
```bash 
sudo apt install qtcreator
```

#### Mandatory:

```bash
sudo apt install build-essential
```

```bash
sudo apt install qt5-default
```

**Install OpenSLL!**

You should now be ready to develop, if you are using VSCode remember to install the correct plugins for Qt development

## CI and Tests 🤖

Pray



[contributors-badge]: https://img.shields.io/github/contributors/RakuJa/ACP-Server "Contributors"

[contributors]: https://github.com/RakuJa/ACP-Server/graphs/contributors "Contributors"

[activity-badge]: https://img.shields.io/github/commit-activity/m/RakuJa/ACP-Server "Activity"

[activity]: https://github.com/RakuJa/ACP-Server/pulse "Activity"

[license-badge]: https://img.shields.io/github/license/RakuJa/ACP-Server
