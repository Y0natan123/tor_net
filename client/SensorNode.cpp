#include <iostream>
#include <chrono>
#include <cstdlib>  // For rand() and srand()
#include <ctime>    // For time() to seed random number generator
#include <sstream>   // נדרש עבור std::ostringstream
#include <iomanip> // For formatting output
#include "SensorNode.h"

#define INVALID_SOCKET  (0)
#define SOCKET_ERROR    (-1)

// Constructor
// Initializes the SensorNode with server IP and database server IP.
// Sets up the database and generates a new key pair.
SensorNode::SensorNode(std::string serverIP, std::string DBserverIP)
    : stopThreads(false)
{
    dockerConfiguraition(serverIP);
    this->DBserverIP  = DBserverIP;
    DB = new SqliteDatabase();
    onionM.GenerateNewKeypair();
}

// Configures the Docker settings for the node.
// Sets the node's IP and destination port.
void SensorNode::dockerConfiguraition(std::string IP){
    this->NODEIP = getMyIP().toString();
    std::cout << "my ip is: " << this->NODEIP << std::endl;   
    this->DESTPORT = 54321;
    this->DESTIP = IP;
}

// Starts communication by launching threads for server and node communication.
void SensorNode::StartCommunication()
{
    PortNlock.lock();
    serverThread = std::thread(&SensorNode::ServerCommunication, this);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    PortNlock.lock();
    startHandleRequestsNode();
}

// Stops communication by terminating threads.
void SensorNode::StopCommunication()
{
    stopThreads = true;
    if (serverThread.joinable())
    {
        serverThread.join();
    }
}

// Handles communication with the server.
// Manages sending and receiving messages, and handles signup and key requests.
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
    std::vector<unsigned char> reqU;  // Request packet in unsigned char vector format
    int pakageId =0;
    std::vector<unsigned char> ciphertext;
    JsonResponsePacketSerializer serializer;  // Serializer to convert object to JSON format
    JsonResponsePacketDeserializer deserializer;  // Deserializer to convert JSON back to object

    std::vector<Node> m_public_Keys;  // Store public keys received from the server
    int choose = 0;  // User menu choice
    bool flag = true;
    std::pair<std::vector<char> , string > portIp;
    std::vector<AESkeysRequest*> m_AES_keys;
    IPv4  myIP ;

    // Function to generate a random port
    size_t bytes_received;
    m_node_port = getRandomPort();
    portRes.port = m_node_port;
    reqU = serializer.serializeResponse(portRes); 




    std::cout <<"try to conect the server port = " << DESTPORT <<" ip = " << DESTIP << "on ip = " +NODEIP<<std::endl;
    TCPRawSocketHandler::sendLongMessage(NODEIP, DESTIP, DESTPORT, std::string(reqU.begin(), reqU.end()));

    portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP, m_node_port,DESTPORT,DESTIP);
    std::string str(portIp.first.begin(), portIp.first.end()); // Convert to string
    int SeverPort = std::stoi(str);    
    std::cout<<"SeverPort:"<<SeverPort<<std::endl;
    // Prepare the signup request packet with the required information
    m_node_to_node_port = getRandomPort();
    PortNlock.unlock();
    signUp.m_port = m_node_to_node_port;
    signUp.m_publicKey = onionM.GetPublicKey();  // Get the public key for the signup
    signUp.m_ip = NODEIP;  // Set the server's IP address
    reqU = serializer.serializeResponse(signUp);  // Serialize the signup request into a byte vector

    // Send the sign up request to the server
    TCPRawSocketHandler::sendLongMessage(NODEIP, DESTIP, SeverPort, std::string(reqU.begin(), reqU.end()),m_node_port);

    portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP, m_node_port,SeverPort);
    bytes_received = portIp.first.size();
    std::vector<unsigned char> resU(portIp.first.begin(), portIp.first.end());
    req = IRequestHandler::makeInfo(resU);  // Parse the response into RequestInfo
    signReq = deserializer.deserializeSignupRequest(req.buffer);  // Deserialize the signup response

    // Check the signup status received from the server
    if (signReq.status == 1) {
        // If signup is successful, enter the menu loop
        while (!stopThreads && flag) {
            std::vector<unsigned char>* resU;
             // Sleep for 3 seconds
            std::this_thread::sleep_for(std::chrono::milliseconds(3000));
            m_public_Keys.clear();
            reqU = serializer.serializeResponse(KeysRes);  // Serialize request for public keys
            TCPRawSocketHandler::sendLongMessage(NODEIP, DESTIP, SeverPort, std::string(reqU.begin(), reqU.end()),m_node_port);
            portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP, m_node_port);
            resU = new std::vector<unsigned char>(portIp.first.begin(), portIp.first.end());
            req = IRequestHandler::makeInfo(*resU);  // Convert the response into RequestInfo
            GetKeysreq = deserializer.deserializeGetKeysRequest(req.buffer);  // Deserialize the request for keys
            pakageId = GetKeysreq.id;
            if (GetKeysreq.isBig) {
                // Handling large arrays of keys
                while (GetKeysreq.isBig) {
                    m_public_Keys.insert(m_public_Keys.end(), GetKeysreq.m_public_Keys.begin(), GetKeysreq.m_public_Keys.end());
                    reqU = serializer.serializeResponse(BigKeysRes);  // Serialize the response with additional keys
                    TCPRawSocketHandler::sendLongMessage(NODEIP, DESTIP, SeverPort, std::string(reqU.begin(), reqU.end()),m_node_port);
                    portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP, m_node_port);
                    resU = new std::vector<unsigned char>(portIp.first.begin(), portIp.first.end());
                    req = IRequestHandler::makeInfo(*resU);  // Convert the response into RequestInfo
                    GetKeysreq = deserializer.deserializeGetKeysRequest(req.buffer);  // Deserialize the request for more keys
                }
            }
            else {
                m_public_Keys.insert(m_public_Keys.end(), GetKeysreq.m_public_Keys.begin(), GetKeysreq.m_public_Keys.end());
            }

            // Displaying the public keys received from the server
            printNetworkNodes(m_public_Keys);

           
           
            // Choosing the message to send
            std::string message;
            std::cout << "Enter the message you want to send: ";
            std::getline(std::cin, message);

            // Serialize the message
            std::vector<unsigned char> messageBytes(message.begin(), message.end());
            std::pair<std::vector<uint8_t>, Node> onionPackage;
            m_public_Keys = SelectRoute(m_public_Keys);  // Select the route for the message
            std::reverse(m_public_Keys.begin(), m_public_Keys.end());
            m_AES_keys = getAesKeysFromNodes(m_public_Keys,pakageId);
            onionPackage = onionM.PrepareOnion(m_public_Keys, messageBytes,m_AES_keys,pakageId);
            std::cout << "Sending message to node: " << onionPackage.second.IP << std::endl;
            SendDataToNode(onionPackage.second, serializer.make(onionPackage.first,NODE_TO_NODE));
                // Handle successful send

        }
    }
}

// Removes the last bit from each byte in the input vector.
std::vector<unsigned char> removeLastBit(const std::vector<unsigned char>& input)
{
    std::vector<unsigned char> output = input;

    for (auto& byte : output)
    {
        byte &= 0xFE; // Clear the last bit (LSB)
    }

    return output;
}

// Retrieves AES keys from nodes using public keys and package ID.
std::vector<AESkeysRequest*> SensorNode::getAesKeysFromNodes(std::vector<Node> m_public_Keys, int pakageId)
{
    JsonResponsePacketSerializer serializer;  // Serializer to convert object to JSON format
    std::vector<unsigned char> reqU;         // Request packet in unsigned char vector format
    getAESKeyResponse getAESKey;
    getAESKey.m_publicKey = onionM.GetPublicKey();
    getAESKey.ID = pakageId;
    std::pair<std::vector<char>, std::string> response;
    RequestInfo req;
    JsonResponsePacketDeserializer deserializer;  // Deserializer to convert JSON back to object
    std::vector<AESkeysRequest*> ret;            // Vector to hold AESkeysRequest pointers

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

            // Add the pointer to the result vector
            ret.push_back(aesKeyRequest);
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            i --;
        }
        

        // Clean up the decrypted response
        delete resU;
    }

    return ret;
}

// Starts handling requests from nodes.
void SensorNode::startHandleRequestsNode()
{
    NodesCommunication();
}

// Manages communication between nodes.
void SensorNode::NodesCommunication()
{
    auto getRandomPort = [](int minPort = 1024, int maxPort = 65535) {
        static std::random_device rd;  // Random number source
        static std::mt19937 gen(rd());  // Random number engine
        std::uniform_int_distribution<> dis(minPort, maxPort);  // Range for port numbers
        return dis(gen);
    };
    int rndPort =0;
    JsonResponsePacketSerializer serializer;  // Serializer to convert object to JSON format
    JsonResponsePacketDeserializer deserializer;
    PortRequest PortS;
    std::pair<std::vector<char> , string > portIp;
    char buffer[1024] = {0};
    json jsonStr;
    PortResponse portRes;
    // Function to generate a random port
    size_t bytes_received;
    std::vector<unsigned char> reqU;  // Request packet in unsigned char vector format
    RequestInfo req;
    while (true)
    {
        try
        {

            portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP,m_node_to_node_port);
            bytes_received = portIp.first.size();

            std::vector<unsigned char> resU(portIp.first.begin(), portIp.first.end());
            req = IRequestHandler::makeInfo(resU);  // Parse the response into RequestInfo
            PortS = deserializer.deserializePortRequest(req.buffer);
            rndPort = getRandomPort();
            portRes.port = rndPort;
            reqU = serializer.serializeResponse(portRes);
            TCPRawSocketHandler::sendLongMessage(NODEIP,portIp.second,PortS.port, std::string(reqU.begin(), reqU.end()));
            std::thread newClient(&SensorNode::handleNewClient, this, rndPort,portIp.second,PortS.port);
            newClient.detach();
        }
        catch (const std::exception&)
        {
            std::cout << "Client faild to connect." << std::endl;
        }
    }




}

// Handles a new client connection.
void SensorNode::handleNewClient(int srcPORT, const string &dstIP, int dstPORT)
{
    // Declare necessary variables for the request handling and packet processing
    RequestInfo reqInfo;
    RequestResult reqResult;
    IRequestHandler IReq;
    std::vector<unsigned char> data;
    ProtoPacket packet;
    std::string IpD;                // Destination IP address
    int PortD;              // Destination port
    std::string IpDString;  // String format of the destination IP
    JsonResponsePacketSerializer serializer;  // Serializer to convert object to JSON format
    JsonResponsePacketDeserializer deserializer;
    std::pair<std::vector<char> , string > portIp;
    std::vector<unsigned char> reqU;  // Request packet in unsigned char vector format
    RSAkeysRequest RSAreq;

    try
    {
        // Buffer for receiving data from the client
        char buffer[BUFFER_SIZE];
        size_t bytes_received;  // Number of bytes received from the client
        size_t dataSize;
        char* charArray = NULL;  // Temporary variable, not used in the code
        std::pair< std::vector<uint8_t>,std::array<uint8_t, BLOCK_SIZE>> aesKey;
        nodeReqAES ReqAES;


        portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP, srcPORT,dstPORT,dstIP);
        bytes_received = portIp.first.size();
        std::vector<unsigned char> ucharVector(portIp.first.begin(), portIp.first.end());
        reqInfo = IReq.makeInfo(ucharVector);
        Node node;
        switch (reqInfo.RequestId)
        {
        case getAESKeyReq:
            RSAreq = deserializer.deserializeRSAkeysRequest(reqInfo.buffer);
            aesKey =  AESCBC::generateRandomKey();
            DB->insertKey(aesKey,RSAreq.ID);
            ReqAES.key = aesKey;
            reqU = serializer.serializeResponse(ReqAES);
            reqU = onionM.EncryptWithPublicKey(RSAreq.key,reqU);

            TCPRawSocketHandler::sendLongMessage(NODEIP,dstIP,dstPORT, std::string(reqU.begin(), reqU.end()),srcPORT);
            break;
        case NODE_TO_NODE:
            node_to_node(reqInfo.buffer,dstIP);
            TCPRawSocketHandler::sendLongMessage(NODEIP,dstIP,dstPORT, "",srcPORT);
            break;
        default:
            break;
        }
   



    }
    catch (const std::exception&)
    {
        std::cout <<"error";
        // Catch any exceptions and handle them (could log or handle specific cases)
    }
}

// Processes node-to-node communication.
void SensorNode::node_to_node(std::vector<unsigned char> ucharVector, const string &dstIP) 
{
    RequestInfo reqInfo;
    RequestResult reqResult;
    IRequestHandler IReq;
    std::vector<unsigned char> data;
    ProtoPacket packet;
    std::string IpD;                // Destination IP address
    int PortD;              // Destination port
    std::string IpDString;  // String format of the destination IP
    JsonResponsePacketSerializer serializer;  // Serializer to convert object to JSON format
    JsonResponsePacketDeserializer deserializer;
    std::pair<std::vector<char> , string > portIp;
    std::pair<std::vector<uint8_t>, std::array<uint8_t, BLOCK_SIZE>> key;
    int packageId = 0;
    for (size_t i = 0; i < 4; ++i) {
        packageId |= static_cast<int>(ucharVector[i]) << (i * 8); // Shift each byte into place
    }   
    ucharVector.erase(ucharVector.begin(), ucharVector.begin() + 4);
    std::cout << "Package ID: " << packageId << std::endl;
    key = DB->getKey(packageId);
    AESCBC aesEncryptor(key);

    // Encrypt the serialized packet (only the body, the header is not encrypted)
    data = aesEncryptor.decrypt(ucharVector);

    // Deserialize the packet data to extract its content
    packet.deserialize(data);
    
    // Process the packet based on its type information (typeInfo field)
    if (validator.CheckOnionReceived(packet))
    {
        if (packet.o_head.typeInfo == 1)  // Type 1 packet (client data packet)
        {
            // Extract destination IP and port from the packet
            IpD = packet.o_head.IPdestination;
            PortD = packet.o_head.PORTdestination;
            IpDString = IpD;  // Convert the integer IP to string format
            std::cout << "Destination Port: " << PortD << std::endl;
            std::cout << "Destination IP: " << IpD << std::endl;
            std::cout << "Destination IP: " << IpDString << std::endl;
            // Set up the server address for connection
            sockaddr_in nodeAddr;
            nodeAddr.sin_family = AF_INET;  // IPv4 address family
            nodeAddr.sin_port = htons(PortD);  // Destination port in network byte order
            Node a;
            a.IP =packet.o_head.IPdestination;
            a.port = packet.o_head.PORTdestination;
            SendDataToNode(a,serializer.make(packet.o_body.encryptedData,NODE_TO_NODE));
            // TODO: Add Onion validator here to ensure that the packet was sent correctly
        }
        else if (packet.o_head.typeInfo == 2)  // Type 2 packet (video file transfer)
        {
            // Video file transfer removed
        }
        else if (packet.o_head.typeInfo == 3) // server directory packet
        { 

            responseToDirector directorRes;
            data = serializer.serializeResponse(directorRes);
            TCPRawSocketHandler::sendLongMessage(NODEIP, dstIP, PortD, std::string(packet.o_body.encryptedData.begin(), packet.o_body.encryptedData.end()));

        }
    }
}

// Sends data to a node and returns the response.
std::pair<std::vector<char>, string> SensorNode::SendDataToNode(const Node& node, const std::vector<unsigned char>& data) {
    auto getRandomPort = [](int minPort = 1024, int maxPort = 65535) {
        static std::random_device rd;  // Random number source
        static std::mt19937 gen(rd());  // Random number engine
        std::uniform_int_distribution<> dis(minPort, maxPort);  // Range for port numbers
        return dis(gen);
    };
    int rndPort =0;
    JsonResponsePacketDeserializer deserializer;
    PortRequest PortS;
    std::pair<std::vector<char> , string > portIp;
    char buffer[1024] = {0};
    json jsonStr;
    // Function to generate a random port
    size_t bytes_received;
    rndPort = getRandomPort();
    std::vector<unsigned char> reqU;  // Request packet in unsigned char vector format
    PortResponse portRes;
    JsonResponsePacketSerializer serializer;  // Serializer to convert object to JSON format
    RequestInfo reqInfo;

    portRes.port = rndPort;
    reqU = serializer.serializeResponse(portRes);

    TCPRawSocketHandler::sendLongMessage(NODEIP, node.IP, node.port, std::string(reqU.begin(), reqU.end()));


    portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP,rndPort);


    bytes_received = portIp.first.size();
    std::vector<unsigned char> resU(portIp.first.begin(), portIp.first.end());
    reqInfo = IRequestHandler::makeInfo(resU);
    PortS = deserializer.deserializePortRequest(reqInfo.buffer);

    TCPRawSocketHandler::sendLongMessage(NODEIP,portIp.second,PortS.port,std::string(data.begin(), data.end()),rndPort);

    portIp = TCPRawSocketHandler::startServerOnOnePORT(NODEIP,rndPort);

    return portIp;


}

// Selects a route for the message using public keys.
std::vector<Node> SensorNode::SelectRoute(std::vector<Node> m_public_Keys, const std::string& destIP) {
    if (m_public_Keys.empty()) {
        std::cerr << "No public keys available to select a route." << std::endl;
        return {};
    }

    std::vector<Node> selectedRoute;
    
    // Find DB/movie server and remove from available nodes
    auto dbServer = std::find_if(m_public_Keys.begin(), m_public_Keys.end(),
                          [this](const Node& node) { 
                              return node.IP == DBserverIP;
                          });
    
    if (dbServer == m_public_Keys.end()) {
        std::cerr << "DB server not found in available nodes" << std::endl;
        return {};
    }

    // Store movie server and remove from available nodes
    Node movieServer = *dbServer;
    m_public_Keys.erase(dbServer);

    // Build route starting with movie server
    selectedRoute.push_back(movieServer);  // First in route (last to receive)
    
    // Add all remaining nodes as intermediate hops
    selectedRoute.insert(selectedRoute.end(), m_public_Keys.begin(), m_public_Keys.end());

    // Debug output
    std::cout << "Route created (in encryption order):\n";
    for (size_t i = 0; i < selectedRoute.size(); i++) {
        std::cout << "Node " << i + 1 << ": " << selectedRoute[i].IP << std::endl;
    }

    return selectedRoute;
}

// Overloaded function to select a route without a destination IP.
std::vector<Node> SensorNode::SelectRoute(std::vector<Node> m_public_Keys) {
    // Call the two-parameter version with empty destIP
    return SelectRoute(std::move(m_public_Keys), "");
}

// Converts a 32-bit integer to an IP address in string format
std::string SensorNode::convertToIP(uint32_t num)
{
    // Split the 32-bit number into 4 octets and convert each one to a string
    return std::to_string((num >> 24) & 0xFF) + "." +  // First octet (most significant byte)
        std::to_string((num >> 16) & 0xFF) + "." +  // Second octet
        std::to_string((num >> 8) & 0xFF) + "." +   // Third octet
        std::to_string(num & 0xFF);                 // Fourth octet (least significant byte)
}

// Displays the menu options to the user
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
        " 5. Exit\n\n"

        " Enter your choice :\n";  // Prompt the user for their choice
}

// Prints network nodes in a table format.
void SensorNode::printNetworkNodes(const std::vector<Node>& m_public_Keys) {

    std::cout << "🌟 Network Nodes Overview 🌟" << std::endl;
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

// Converts a public key to a hexadecimal string.
std::string SensorNode::publicKeyToHex(const std::pair<uint64_t, uint64_t>& public_Key) {
    std::ostringstream hexStream;  // Output stream for the hex string

    // Convert the first uint64_t (first part of the pair)
    hexStream << std::hex << std::setw(16) << std::setfill('0') << public_Key.first;

    // Convert the second uint64_t (second part of the pair)
    hexStream << std::hex << std::setw(16) << std::setfill('0') << public_Key.second;

    // Return the concatenated hex string
    return hexStream.str();
}

// Overloads the << operator to print an IPv4 address.
std::ostream& operator<<(std::ostream& os, const IPv4& ip) {
    os << (int)ip.b1 << "." << (int)ip.b2 << "." << (int)ip.b3 << "." << (int)ip.b4;
    return os;
}

// Retrieves the current machine's IP address.
IPv4 SensorNode::getMyIP() {
    IPv4 myIP;
    char szBuffer[1024];
    if (gethostname(szBuffer, sizeof(szBuffer)) == -1) { // Fix for Linux
        return myIP;
    }
    struct hostent *host = gethostbyname(szBuffer);
    if (host == NULL) {
        return myIP;
    }
    struct in_addr* addr = (struct in_addr*)host->h_addr; // Get IP
    uint32_t ip = ntohl(addr->s_addr); // Convert from network byte order to host byte order
    myIP.b1 = (ip >> 24) & 0xFF;
    myIP.b2 = (ip >> 16) & 0xFF;
    myIP.b3 = (ip >> 8) & 0xFF;
    myIP.b4 = ip & 0xFF;
    return myIP;
}

// Resolves a hostname to an IP address.
std::string SensorNode::getIPAddressFromName(const std::string& hostname) {
    struct addrinfo hints, * res;
    char ipStr[INET_ADDRSTRLEN];

    // Initialize hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;        // IPv4
    hints.ai_socktype = SOCK_STREAM;  // TCP stream sockets

    // Get address info
    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0) {
        std::cerr << "Failed to resolve hostname: " << hostname << std::endl;
        return "";
    }

    // Convert the first IP found to string format
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, INET_ADDRSTRLEN);

    freeaddrinfo(res);  // Free the linked list

    return std::string(ipStr);  // Return IP address as a string

}