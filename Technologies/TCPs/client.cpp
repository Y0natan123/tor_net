#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "TCP.h"

#define SERVER_IP "127.0.0.1"  // Replace with the actual server IP
#define SERVER_PORT 54321           // Replace with the server port

int main() {
    const std::string srcIP = "127.0.0.1";  // Replace with the client's IP
    const std::string dstIP = SERVER_IP;

    try {

        std::string segments = "Hello, this is segment 1.";


        // Initialize raw socket
        TCPRawSocketHandler::sendLongMessage(srcIP,dstIP,SERVER_PORT,segments);
        
        std::cout << "All segments sent successfully.\n";


    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

}
