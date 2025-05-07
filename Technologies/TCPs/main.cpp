#include "TCP.h"
#include <iostream>
#include <vector>
#include <string>

int main() {
    // Example IPs and a long message
    string srcIP = "127.0.0.1";
    string dstIP = "127.0.0.1";
    string longMessage = "This is a very long message that will be split into segments and sent using raw sockets. ";

    TCPRawSocketHandler::startServerOnOnePORT(srcIP,54321);

    return 0;
}
