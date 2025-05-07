#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <thread>
#include <sstream>
#include <random>
#include "ProtoPacket.h"        // Ensure you have the definition of ProtoPacket
#include "TCP.h"
#include "IRequestHandler.h"
#include "Sink.h"

#define BUFFER_SIZE 1024
#define INVALID_SOCKET (0)
#define SOCKET_ERROR (-1)

/**
 * @brief Structure representing an IPv4 address.
 */
struct IPv4 {
    unsigned char b1, b2, b3, b4;  ///< IPv4 address components
    
    /**
     * @brief Converts the IPv4 address to a string.
     * @return The IPv4 address as a string in dot notation.
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
     * @brief Converts a string to an IPv4 structure.
     * @param ip The IPv4 address string.
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

    /**
     * @brief Overloads the stream output operator for IPv4 structure.
     */
    friend std::ostream& operator<<(std::ostream& os, const IPv4& ip);
};

/**
 * @brief Class responsible for managing client communication.
 */
class Communicator {
private:
    Sink directorServer; ///< Handles requests directed to the server
    std::map<int, int> m_clients; ///< Maps sockets to request handlers
    std::mutex m_mutex; ///< Mutex for thread safety
    IRequestHandler requestHandl; ///< Handles incoming requests
    std::thread nodesThread; ///< Thread for checking network nodes

    std::string SERVER_IP = "127.0.0.1"; ///< Server IP Address
    int serverPORT = 54321; ///< Server Port Number

    int m_serverSocket; ///< Server socket descriptor

    /**
     * @brief Configures the Docker environment.
     */
    void dockerConfiguraition();

    /**
     * @brief Handles new client connections.
     * @param srcPORT Source port of the client.
     * @param dstIP Destination IP address.
     * @param dstPORT Destination port.
     */
    void handleNewClient(int srcPORT, const std::string &dstIP, int dstPORT);

    /**
     * @brief Handles client disconnections.
     * @param clientSocket Socket descriptor of the client.
     */
    void handleClientDisconnection(int clientSocket);

    /**
     * @brief Retrieves the IP address from a hostname.
     * @param hostname The hostname to resolve.
     * @return The corresponding IP address as a string.
     */
    std::string getIPAddressFromName(const std::string& hostname);

public:

    /**
     * @brief Constructor for Communicator.
     */
    Communicator();

    
    /**
     * @brief Retrieves the local IP address of the machine.
     * @return The local IPv4 address.
     */
    IPv4 getMyIP();

    
    /**
     * @brief Starts the server.
     */
    void Startserver();
    
    /**
     * @brief Binds the socket and listens for incoming connections.
     */
    void bindAndListen();
    
    /**
     * @brief Starts checking active network nodes.
     */
    void startCheckNodes();
    
    /**
     * @brief Initiates communication with clients.
     */
    void StartCommunication();
    
    /**
     * @brief Handles incoming client requests.
     */
    void startHandleRequests();
};
