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
#include "massageHandling.h"
#include "TCP.h"

#define BUFFER_SIZE 1024

/**
 * IPv4 address structure
 * Represents an IPv4 address with utility methods
 */
struct IPv4 {
    unsigned char b1, b2, b3, b4;
    
    /**
     * Converts the IPv4 address to a string representation
     * @return String in format "b1.b2.b3.b4"
     */
    std::string toString() const {
        std::ostringstream oss;
        oss << static_cast<int>(b1) << "."
            << static_cast<int>(b2) << "."
            << static_cast<int>(b3) << "."
            << static_cast<int>(b4);
        return oss.str();
    }

    /**
     * Parses an IP address string into the IPv4 structure
     * @param ip The IP address string in format "b1.b2.b3.b4"
     */
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
    
    // Declare friend function for output stream
    friend std::ostream& operator<<(std::ostream& os, const IPv4& ip);
};

/**
 * SensorNode class
 * Represents a node in the onion routing network
 */
class SensorNode {
private:
    SqliteDatabase* DB;                  // Database connection
    std::queue<NextNode> packageList;    // List of packages to be processed
    std::mutex packaMutex;               // Mutex for package list access
    std::mutex inputMutex;               // Mutex for input handling
    int socketFd;                        // Socket file descriptor
    int m_node_port;                     // Port for node communications
    std::mutex PortNlock;                // Mutex for port number access
    int m_node_to_node_port;             // Port for node-to-node communications
    std::string NODEIP = "127.0.0.1";    // Local IP address
    std::string DESTIP = "127.0.0.1";    // Destination IP address
    int DESTPORT = 54321;                // Destination port
    std::thread serverThread;            // Thread for server communication
    bool stopThreads;                    // Flag to stop threads
    OnionManager onionM;                 // Onion routing manager
    OnionValidator validator;            // Validator for onion packets
    massageHandling m_massage;           // Message handling
    std::string fileName = "../masage.txt"; // File for message storage
    std::vector<Node> m_public_Keys;      // Public keys of other nodes
    std::vector<AESkeysRequest*> m_AES_keys; // AES keys for encryption

    /**
     * Handles communication with the server
     * Registers the node and exchanges keys
     */
    void ServerCommunication();
    
    /**
     * Closes the TCP connection
     */
    void CloseTcpConnection();
    
    /**
     * Starts the thread to handle requests from other nodes
     */
    void startHandleRequestsNode();
    
    /**
     * Manages communication between nodes
     * Listens for incoming connections
     */
    void NodesCommunication();
    
    /**
     * Handles a new client connection
     * @param srcPORT Source port for communication
     * @param dstIP Destination IP address
     * @param dstPORT Destination port
     */
    void handleNewClient(int srcPORT, const std::string &dstIP, int dstPORT);
    
    /**
     * Processes node-to-node communication
     * @param ucharVector Data vector received from another node
     * @param dstIP Destination IP address
     */
    void node_to_node(std::vector<unsigned char> ucharVector, const std::string &dstIP);
    
    /**
     * Selects a route through multiple nodes
     * @param m_public_Keys Available nodes
     * @return Vector of nodes forming the route
     */
    std::vector<Node> SelectRoute(std::vector<Node> m_public_Keys);
    
    /**
     * Selects a route to a specific destination
     * @param m_public_Keys Available nodes
     * @param destIP Destination IP
     * @return Vector of nodes forming the route
     */
    std::vector<Node> SelectRoute(std::vector<Node> m_public_Keys, const std::string& destIP);
    
    /**
     * Convert a 32-bit integer to an IP address string
     * @param num 32-bit IP address
     * @return IP address in string format
     */
    std::string convertToIP(uint32_t num);
    
    /**
     * Converts a public key to hex string for display
     * @param public_Key The public key to convert
     * @return Hex string representation of the key
     */
    std::string publicKeyToHex(const std::pair<uint64_t, uint64_t>& public_Key);
    
    /**
     * Displays the list of available nodes
     * @param m_public_Keys List of nodes to display
     */
    void printNetworkNodes(const std::vector<Node>& m_public_Keys);
    
    /**
     * Displays the menu for the node
     */
    void printmenu();
    
    /**
     * Gets AES keys from nodes for secure communication
     * @param m_public_Keys List of nodes to get keys from
     * @param pakageId The ID of the package
     * @return Vector of AES key requests
     */
    std::vector<AESkeysRequest*> getAesKeysFromNodes(std::vector<Node> m_public_Keys, int pakageId);
    
    /**
     * Gets the local IP address
     * @return IPv4 address of this machine
     */
    IPv4 getMyIP();
    
    /**
     * Resolves a hostname to an IP address
     * @param hostname The hostname to resolve
     * @return IP address in string format
     */
    std::string getIPAddressFromName(const std::string& hostname);
    
    /**
     * Configures the node's network settings
     * @param IP The IP address of the database server
     */
    void dockerConfiguraition(std::string IP);
    
public:
    /**
     * Constructor for SensorNode
     * Initializes the node, configures network settings, and generates encryption keypair
     * @param IP The IP address of the DB server
     */
    SensorNode(std::string IP);
    
    /**
     * Starts communication threads for server and node communications
     */
    void StartCommunication();
    
    /**
     * Stops all communication threads
     */
    void StopCommunication();
    
    /**
     * Closes the connection
     */
    void CloseConnection();
    
    /**
     * Sends data to another node
     * @param node The target node
     * @param data The data to send
     * @return Response from the node
     */
    std::pair<std::vector<char>, std::string> SendDataToNode(const Node& node, const std::vector<unsigned char>& data);
};


#endif // SENSORNODE_H
