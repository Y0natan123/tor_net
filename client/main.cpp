#include <iostream>
#include "ProtoPacket.h"
#include "SensorNode.h"
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <SERVER_IP> <DBSERVER_IP>" << std::endl;
        return 1;
    }

    std::string server_ip = argv[1];
    std::string dbserver_ip = argv[2];

    std::cout << "Starting SensorNode with IPs - Server: " << server_ip << ", DB Server: " << dbserver_ip << std::endl;

    try {
        SensorNode node(server_ip, dbserver_ip);
        node.StartCommunication();
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}