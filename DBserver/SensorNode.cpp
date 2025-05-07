#include "SensorNode.h"
#include <iostream>
#include <chrono>
#include <cstdlib>  // For rand() and srand()
#include <ctime>    // For time() to seed random number generator
#include <sstream>   // נדרש עבור std::ostringstream
#include <iomanip> // For formatting output

#define INVALID_SOCKET  (0)
#define SOCKET_ERROR    (-1)

/**
 * Constructor for SensorNode
 * Initializes the node, configures network settings, and generates encryption keypair
 * @param IP The IP address of the DB server
 */
SensorNode::SensorNode(std::string IP)
    : stopThreads(false)
{
    dockerConfiguraition(IP);
    DB = new SqliteDatabase();
    onionM.GenerateNewKeypair();
}

/**
 * Configures the node's network settings
 * @param IP The IP address of the database server
 */
void SensorNode::dockerConfiguraition(std::string IP){
    this->NODEIP = getMyIP().toString();
    this->DESTPORT = 54321;
    std::cout << "Dserver: " + IP; 
    this->DESTIP = IP;
    this->m_node_port = 44455;
}

/**
 * Starts communication threads for server and node communications
 */
void SensorNode::StartCommunication()
{
    PortNlock.lock();
    serverThread = std::thread(&SensorNode::ServerCommunication, this);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    PortNlock.lock();
    startHandleRequestsNode();
}

/**
 * Stops all communication threads
 */
void SensorNode::StopCommunication()
{
    stopThreads = true;
    if (serverThread.joinable())
    {
        serverThread.join();
    }
}

/**
 * Handles communication with the server
 * Registers the node with the server and manages key exchanges
 */
void SensorNode::ServerCommunication() {
    auto getRandomPort = [](int minPort = 1024, int maxPort = 65535) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(minPort, maxPort);
        return dis(gen);
    };

    // Declare necessary variables and objects
    RequestInfo req;
    IRequestHandler IReq;
    GetKeysRequest GetKeysreq;
    GetBigKeysResponse BigKeysRes;
    PortResponse portRes;
    SignupResponse signUp;
    GetKeysResponse KeysRes;
    SignupRequest signReq;
    std::vector<unsigned char> reqU;
    int pakageId = 0;
    std::vector<unsigned char> ciphertext;
    JsonResponsePacketSerializer serializer;
    JsonResponsePacketDeserializer deserializer;

    std::vector<Node> m_public_Keys;
    int choose = 0;
    bool flag = true;
    std::pair<std::vector<char>, string> portIp;
    std::vector<AESkeysRequest*> m_AES_keys;
    IPv4 myIP;

    size_t bytes_received;
    m_node_port = getRandomPort();
    portRes.port = m_node_port;
    reqU = serializer.serializeResponse(portRes); 

    std::cout << "Connecting to server port = " << DESTPORT << " ip = " << DESTIP << " on ip = " + NODEIP << std::endl;
    TCPRawSocketHandler::sendLongMessage(NODEIP, DESTIP, DESTPORT, std::string(reqU.begin(), reqU.end()));

    portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP, m_node_port, DESTPORT, DESTIP);
    std::string str(portIp.first.begin(), portIp.first.end());
    int SeverPort = std::stoi(str);    
    std::cout << "SeverPort:" << SeverPort << std::endl;
    
    // Prepare the signup request packet
    m_node_to_node_port = getRandomPort();
    PortNlock.unlock();
    signUp.m_port = m_node_to_node_port;
    signUp.m_publicKey = onionM.GetPublicKey();
    signUp.m_ip = NODEIP;
    reqU = serializer.serializeResponse(signUp);

    // Send the sign up request to the server
    TCPRawSocketHandler::sendLongMessage(NODEIP, DESTIP, SeverPort, std::string(reqU.begin(), reqU.end()), m_node_port);

    portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP, m_node_port, SeverPort);
    bytes_received = portIp.first.size();
    std::vector<unsigned char> resU(portIp.first.begin(), portIp.first.end());
    req = IRequestHandler::makeInfo(resU);
    signReq = deserializer.deserializeSignupRequest(req.buffer);

    // Check the signup status received from the server
    if (signReq.status == 1) {
        // Successfully signed up
    }
}

/**
 * Gets AES keys from nodes for secure communication
 * @param m_public_Keys List of nodes to get keys from
 * @param pakageId The ID of the package
 * @return Vector of AES key requests
 */
std::vector<AESkeysRequest*> SensorNode::getAesKeysFromNodes(std::vector<Node> m_public_Keys, int pakageId)
{
    JsonResponsePacketSerializer serializer;
    std::vector<unsigned char> reqU;
    getAESKeyResponse getAESKey;
    getAESKey.m_publicKey = onionM.GetPublicKey();
    getAESKey.ID = pakageId;
    std::pair<std::vector<char>, std::string> response;
    RequestInfo req;
    JsonResponsePacketDeserializer deserializer;
    std::vector<AESkeysRequest*> ret;

    // Serialize the response with additional keys
    reqU = serializer.serializeResponse(getAESKey);

    for (size_t i = 0; i < m_public_Keys.size(); i++)
    {
        // Send data to node and get response
        response = SendDataToNode(m_public_Keys[i], reqU);

        // Convert response to unsigned char vector and decrypt
        std::vector<unsigned char>* resU = new std::vector<unsigned char>(response.first.begin(), response.first.end());
        *resU = onionM.DecryptLayer(*resU);

        // Convert the response into RequestInfo
        req = IRequestHandler::makeInfo(*resU);

        try
        {
            // Deserialize the buffer into AESkeysRequest
            AESkeysRequest* aesKeyRequest = new AESkeysRequest(deserializer.deserializeAESkeysRequest(req.buffer));
            ret.push_back(aesKeyRequest);
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            i--;
        }

        delete resU;
    }

    return ret;
}

/**
 * Starts the node communication handler thread
 */
void SensorNode::startHandleRequestsNode()
{
    NodesCommunication();
}

/**
 * Handles communication between nodes
 * Listens for incoming connections from other nodes
 */
void SensorNode::NodesCommunication()
{
    auto getRandomPort = [](int minPort = 1024, int maxPort = 65535) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(minPort, maxPort);
        return dis(gen);
    };
    
    int rndPort = 0;
    JsonResponsePacketSerializer serializer;
    JsonResponsePacketDeserializer deserializer;
    PortRequest PortS;
    std::pair<std::vector<char>, string> portIp;
    PortResponse portRes;
    std::vector<unsigned char> reqU;
    RequestInfo req;
    
    while (true)
    {
        try
        {
            portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP, m_node_to_node_port);
            
            std::vector<unsigned char> resU(portIp.first.begin(), portIp.first.end());
            req = IRequestHandler::makeInfo(resU);
            PortS = deserializer.deserializePortRequest(req.buffer);
            rndPort = getRandomPort();
            portRes.port = rndPort;
            reqU = serializer.serializeResponse(portRes);
            TCPRawSocketHandler::sendLongMessage(NODEIP, portIp.second, PortS.port, std::string(reqU.begin(), reqU.end()));
            std::thread newClient(&SensorNode::handleNewClient, this, rndPort, portIp.second, PortS.port);
            newClient.detach();
        }
        catch (const std::exception&)
        {
            std::cout << "Client failed to connect." << std::endl;
        }
    }
}

/**
 * Handles a new client connection
 * @param srcPORT Source port for communication
 * @param dstIP Destination IP address
 * @param dstPORT Destination port
 */
void SensorNode::handleNewClient(int srcPORT, const string &dstIP, int dstPORT)
{
    RequestInfo reqInfo;
    RequestResult reqResult;
    IRequestHandler IReq;
    std::vector<unsigned char> data;
    ProtoPacket packet;
    std::string IpD;
    int PortD;
    std::string IpDString;
    JsonResponsePacketSerializer serializer;
    JsonResponsePacketDeserializer deserializer;
    std::pair<std::vector<char>, string> portIp;
    std::vector<unsigned char> reqU;
    RSAkeysRequest RSAreq;

    try
    {
        char buffer[BUFFER_SIZE];
        size_t bytes_received;
        size_t dataSize;
        char* charArray = NULL;
        std::pair<std::vector<uint8_t>, std::array<uint8_t, BLOCK_SIZE>> aesKey;
        nodeReqAES ReqAES;

        portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP, srcPORT, dstPORT, dstIP);
        bytes_received = portIp.first.size();
        std::vector<unsigned char> ucharVector(portIp.first.begin(), portIp.first.end());
        reqInfo = IReq.makeInfo(ucharVector);
        Node node;
        
        switch (reqInfo.RequestId)
        {
        case getAESKeyReq:
            RSAreq = deserializer.deserializeRSAkeysRequest(reqInfo.buffer);
            aesKey = AESCBC::generateRandomKey();
            DB->insertKey(aesKey, RSAreq.ID);
            ReqAES.key = aesKey;
            reqU = serializer.serializeResponse(ReqAES);
            reqU = onionM.EncryptWithPublicKey(RSAreq.key, reqU);

            TCPRawSocketHandler::sendLongMessage(NODEIP, dstIP, dstPORT, std::string(reqU.begin(), reqU.end()), srcPORT);
            break;
        case NODE_TO_NODE:
            node_to_node(reqInfo.buffer, dstIP);
            TCPRawSocketHandler::sendLongMessage(NODEIP, dstIP, dstPORT, "", srcPORT);
            break;
        default:
            break;
        }
    }
    catch (const std::exception&)
    {
        std::cout << "Error in handleNewClient";
    }
}

/**
 * Processes node-to-node communication
 * @param ucharVector Data vector received from another node
 * @param dstIP Destination IP address
 */
void SensorNode::node_to_node(std::vector<unsigned char> ucharVector, const string &dstIP) {
    RequestInfo reqInfo;
    IRequestHandler IReq;
    std::vector<unsigned char> data;
    ProtoPacket packet;
    std::string IpD;
    int PortD;
    std::string IpDString;
    JsonResponsePacketSerializer serializer;
    std::pair<std::vector<uint8_t>, std::array<uint8_t, BLOCK_SIZE>> key;
    int packageId = 0;
    
    // Extract package ID from first 4 bytes
    for (size_t i = 0; i < 4; ++i) {
        packageId |= static_cast<int>(ucharVector[i]) << (i * 8);
    }   
    ucharVector.erase(ucharVector.begin(), ucharVector.begin() + 4);

    // Get the key for this package and decrypt data
    key = DB->getKey(packageId);
    AESCBC aesEncryptor(key);
    data = aesEncryptor.decrypt(ucharVector);

    // Deserialize the packet data to extract its content
    packet.deserialize(data);

    // Process the packet based on its type
    if (validator.CheckOnionReceived(packet))
    {
        if (packet.o_head.typeInfo == 1)  // Type 1 packet (client data packet)
        {
            // Extract destination IP and port from the packet
            IpD = packet.o_head.IPdestination;
            PortD = packet.o_head.PORTdestination;
            IpDString = IpD;
            
            // Set up connection data
            Node a;
            a.IP = IpD;
            a.port = PortD;
            
            // Forward the packet to next destination
            SendDataToNode(a, serializer.make(packet.o_body.encryptedData, NODE_TO_NODE));
        }
        else if (packet.o_head.typeInfo == 2)  
        {  
            if (packet.o_body.encryptedData.empty()) {
                return;
            }
            
            // Extract request type, source IP and port
            uint8_t requestType = packet.o_body.encryptedData[0];
            size_t offset = 1;
            
            uint8_t ipLength = packet.o_body.encryptedData[offset++];
            std::string sourceIP(packet.o_body.encryptedData.begin() + offset, 
                                packet.o_body.encryptedData.begin() + offset + ipLength);
            offset += ipLength;
            
            int sourcePort = *reinterpret_cast<const int*>(&packet.o_body.encryptedData[offset]);
            
            // Request types are handled here
            // Code for handling different request types (movie-related code removed)
        }
        else if (packet.o_head.typeInfo == 3) // server directory packet
        { 
            responseToDirector directorRes;
            data = serializer.serializeResponse(directorRes);
            TCPRawSocketHandler::sendLongMessage(NODEIP, dstIP, PortD, std::string(packet.o_body.encryptedData.begin(), packet.o_body.encryptedData.end()));
        }
    }
}

/**
 * Sends data to another node
 * @param node The target node
 * @param data The data to send
 * @return Response from the node
 */
std::pair<std::vector<char>, string> SensorNode::SendDataToNode(const Node& node, const std::vector<unsigned char>& data) {
    auto getRandomPort = [](int minPort = 1024, int maxPort = 65535) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(minPort, maxPort);
        return dis(gen);
    };
    
    int rndPort = getRandomPort();
    JsonResponsePacketDeserializer deserializer;
    PortRequest PortS;
    std::pair<std::vector<char>, string> portIp;
    PortResponse portRes;
    JsonResponsePacketSerializer serializer;
    RequestInfo reqInfo;
    
    // Initialize port response and send it
    portRes.port = rndPort;
    std::vector<unsigned char> reqU = serializer.serializeResponse(portRes);
    TCPRawSocketHandler::sendLongMessage(NODEIP, node.IP, node.port, std::string(reqU.begin(), reqU.end()));

    // Wait for response
    portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP, rndPort);
    std::vector<unsigned char> resU(portIp.first.begin(), portIp.first.end());
    reqInfo = IRequestHandler::makeInfo(resU);
    PortS = deserializer.deserializePortRequest(reqInfo.buffer);

    // Send actual data
    TCPRawSocketHandler::sendLongMessage(NODEIP, portIp.second, PortS.port, std::string(data.begin(), data.end()), rndPort);

    // Wait for final response
    portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP, rndPort);
    return portIp;
}

/**
 * Selects a route through multiple nodes
 * @param m_public_Keys Available nodes
 * @param destIP Destination IP
 * @return Vector of nodes forming the route
 */
std::vector<Node> SensorNode::SelectRoute(std::vector<Node> m_public_Keys, const std::string& destIP) {
    // Find the destination node
    auto it = std::find_if(m_public_Keys.begin(), m_public_Keys.end(),
                          [&destIP](const Node& node) { return node.IP == destIP; });
    
    if (it != m_public_Keys.end()) {
        Node destNode = *it;
        m_public_Keys.erase(it);
        
        // Create route with random nodes first
        std::vector<Node> selectedRoute;
        
        // Add 2-4 random nodes
        int additionalNodes = 2 + (rand() % 3); // Random number between 2-4
        for (int i = 0; i < additionalNodes && !m_public_Keys.empty(); ++i) {
            int randomIndex = rand() % m_public_Keys.size();
            selectedRoute.push_back(m_public_Keys[randomIndex]);
            m_public_Keys.erase(m_public_Keys.begin() + randomIndex);
        }
        
        // Add destination node last
        selectedRoute.push_back(destNode);
        
        return selectedRoute;
    }
    return {};
}

/**
 * Convert a 32-bit integer to an IP address string
 * @param num 32-bit IP address
 * @return IP address in string format
 */
std::string SensorNode::convertToIP(uint32_t num)
{
    return std::to_string((num >> 24) & 0xFF) + "." +
           std::to_string((num >> 16) & 0xFF) + "." +
           std::to_string((num >> 8) & 0xFF) + "." +
           std::to_string(num & 0xFF);
}

/**
 * Resolves a hostname to an IP address
 * @param hostname The hostname to resolve
 * @return IP address in string format
 */
std::string SensorNode::getIPAddressFromName(const std::string& hostname) {
    struct addrinfo hints, * res;
    char ipStr[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0) {
        std::cerr << "Failed to resolve hostname: " << hostname << std::endl;
        return "";
    }

    struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, INET_ADDRSTRLEN);

    freeaddrinfo(res);
    return std::string(ipStr);
}

/**
 * Output stream operator for IPv4 addresses
 */
std::ostream& operator<<(std::ostream& os, const IPv4& ip) {
    os << (int)ip.b1 << "." << (int)ip.b2 << "." << (int)ip.b3 << "." << (int)ip.b4;
    return os;
}

/**
 * Gets the local IP address
 * @return IPv4 address of this machine
 */
IPv4 SensorNode::getMyIP() {
    IPv4 myIP;
    char szBuffer[1024];
    if (gethostname(szBuffer, sizeof(szBuffer)) == -1) {
        return myIP;
    }
    struct hostent *host = gethostbyname(szBuffer);
    if (host == NULL) {
        return myIP;
    }
    struct in_addr* addr = (struct in_addr*)host->h_addr;
    uint32_t ip = ntohl(addr->s_addr);
    myIP.b1 = (ip >> 24) & 0xFF;
    myIP.b2 = (ip >> 16) & 0xFF;
    myIP.b3 = (ip >> 8) & 0xFF;
    myIP.b4 = ip & 0xFF;
    return myIP;
}

/**
 * Displays the menu for the node
 */
void SensorNode::printmenu()
{
    std::cout <<
        " ==========================\n"
        " TOR Network Menu\n"
        " ==========================\n\n"
        " 1. Send a message to another computer\n"
        " 2. Check received messages\n"
        " 3. View network status\n"
        " 4. Configure node settings\n"
        " 5. Exit\n\n";
}

/**
 * Displays the list of available nodes
 * @param m_public_Keys List of nodes to display
 */
void SensorNode::printNetworkNodes(const std::vector<Node>& m_public_Keys) {
    std::cout << "🌟 Nodes Overview 🌟" << std::endl;
    std::cout << std::string(70, '=') << std::endl;

    // Print table header
    std::cout << std::left << std::setw(5) << "ID"
        << std::setw(20) << "IP Address"
        << std::setw(10) << "Port"
        << "Public Key" << std::endl;
    std::cout << std::string(70, '-') << std::endl;

    // Print each node
    for (size_t i = 0; i < m_public_Keys.size(); ++i) {
        const Node& node = m_public_Keys[i];
        std::cout << std::left << std::setw(5) << i + 1
            << std::setw(20) << node.IP
            << std::setw(10) << node.port
            << publicKeyToHex(node.public_Key) << std::endl;
    }

    std::cout << std::string(70, '=') << std::endl;
    std::cout << "✨ Total Nodes: " << m_public_Keys.size() << " ✨" << std::endl;
}

/**
 * Converts a public key to hex string for display
 * @param public_Key The public key to convert
 * @return Hex string representation of the key
 */
std::string SensorNode::publicKeyToHex(const std::pair<uint64_t, uint64_t>& public_Key) {
    std::ostringstream hexStream;
    hexStream << std::hex << std::setw(16) << std::setfill('0') << public_Key.first;
    hexStream << std::hex << std::setw(16) << std::setfill('0') << public_Key.second;
    return hexStream.str();
}