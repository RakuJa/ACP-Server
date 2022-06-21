g++ -Wall -ggdb3 client.cpp ../lib/certificate.cpp ../lib/hash.cpp ../lib/key_handle.cpp ../lib/operation_package.cpp -o client -lcrypto
./client 127.0.0.1 25565
