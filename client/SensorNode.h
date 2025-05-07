#ifndef SENSORNODE_H
#define SENSORNODE_H

#pragma comment (lib, "ws2_32.lib")

#include <string>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include "SqliteDatabase.h"
#include <random>
#include "OnionManager.h"
#include "IRequestHandler.h"
#include "JsonResponsePacketDeserializer.h"
#include "JsonResponsePacketSerializer.h"
#include "OnionValidator.h"
#include "TCP.h"

#define BUFFER_SIZE 1024

struct IPv4 {
    unsigned char b1, b2, b3, b4;
    std::string toString() const {
        std::ostringstream oss;
        oss << static_cast<int>(b1) << "."
            << static_cast<int>(b2) << "."
            << static_cast<int>(b3) << "."
            << static_cast<int>(b4);
        return oss.str();
    }

    // Convert string to IPv4 struct
    void toIPv4(const std::string& ip) {
        std::istringstream iss(ip);
        int part1, part2, part3, part4;
        char dot1, dot2, dot3;

        if (iss >> part1 >> dot1 >> part2 >> dot2 >> part3 >> dot3 >> part4 &&
            dot1 == '.' && dot2 == '.' && dot3 == '.') {
            b1 = static_cast<unsigned char>(part1);
            b2 = static_cast<unsigned char>(part2);
            b3 = static_cast<unsigned char>(part3);
            b4 = static_cast<unsigned char>(part4);
        } else {
            std::cerr << "Invalid IP format: " << ip << std::endl;
        }
    }
    // Declare friend function so it can access private members (if nee
    friend std::ostream& operator<<(std::ostream& os, const IPv4& ip);
};

// Forward declarations
class SensorNode {
private:
    SqliteDatabase* DB;
    std::queue<NextNode> packageList;
    std::mutex packaMutex;
    std::mutex inputMutex;
    int socketFd;
    int m_node_port;
    std::mutex PortNlock;
    int m_node_to_node_port;
    std::string NODEIP = "127.0.0.1";
    std::string DESTIP = "127.0.0.1";
    int DESTPORT = 54321;
    std::thread serverThread;
    bool stopThreads;
    OnionManager onionM;
    OnionValidator validator;
    std::string DBserverIP;
    void ServerCommunication();
    void CloseTcpConnection();
    void startHandleRequestsNode();
    void NodesCommunication();
    void handleNewClient(int srcPORT, const std::string &dstIP, int dstPORT);
    void node_to_node(std::vector<unsigned char> ucharVector, const std::string &dstIP);
    std::vector<Node> SelectRoute(std::vector<Node> m_public_Keys);
    std::vector<Node> SelectRoute(std::vector<Node> m_public_Keys, const std::string& destIP);
    std::string convertToIP(uint32_t num);
    std::string publicKeyToHex(const std::pair<uint64_t, uint64_t>& public_Key);
    void printNetworkNodes(const std::vector<Node>& m_public_Keys);
    void printmenu();
    std::vector<AESkeysRequest*> getAesKeysFromNodes(std::vector<Node> m_public_Keys, int pakageId);
    IPv4 getMyIP();
    std::string getIPAddressFromName(const std::string& hostname);
    void dockerConfiguraition(std::string IP);
public:
    SensorNode(std::string serverIP,std::string DBserverIP);
    void StartCommunication();
    void StopCommunication();
    void CloseConnection();
    std::pair<std::vector<char>, std::string> SendDataToNode(const Node& node, const std::vector<unsigned char>& data);
};


#endif // SENSORNODE_H
