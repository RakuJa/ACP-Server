g++ -Wall -ggdb3 client.cpp ../lib/certificate.cpp ../lib/hash.cpp ../lib/key_handle.cpp ../lib/operation_package.cpp ../lib/network.cpp -o client -lcrypto -lpthread
./client 127.0.0.1 25565
