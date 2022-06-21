g++ -Wall -ggdb3 server.cpp ../lib/certificate.cpp ../lib/hash.cpp ../lib/key_handle.cpp ../lib/operation_package.cpp -o server -lcrypto
./server 25565
