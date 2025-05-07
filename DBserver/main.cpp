#include <iostream>
#include "ProtoPacket.h"
#include "SensorNode.h"
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <IP_ADDRESS>" << std::endl;
        return 1;
    }

    std::string ip_address = argv[1]; // מקבל את כתובת ה-IP מהפרמטר הראשון

    std::cout << "Starting SensorNode with IP: " << ip_address << std::endl;

    SensorNode node = SensorNode(ip_address); // מעביר את ה-IP לאובייקט SensorNode
    node.StartCommunication();

    return 0;
}