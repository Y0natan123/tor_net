#include "Communicator.h"
#include <iostream>
#include <chrono>
#include <cstdlib>  // For rand() and srand()
#include <ctime>    // For time() to seed random number generator
#include <sstream>   // נדרש עבור std::ostringstream
#include <iomanip> // For formatting output




// Constructor
Communicator::Communicator()
    : m_serverSocket(INVALID_SOCKET) {
    dockerConfiguraition();
    directorServer.~Sink();
    
}


void Communicator::dockerConfiguraition(){
    this->SERVER_IP = getMyIP().toString();
    this->serverPORT = 54321;

}


void Communicator::StartCommunication()
{
    nodesThread = std::thread(&Communicator::startCheckNodes, this);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}


void Communicator::Startserver()
{

}

void Communicator::bindAndListen()
{
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
    while (true)
    {
        try
        {
            portIp = TCPRawSocketHandler::startServerOnOnePORT(SERVER_IP,54321);
            bytes_received = portIp.first.size();
            std::vector<unsigned char> resU(portIp.first.begin(), portIp.first.end());
            PortS = deserializer.deserializePortRequest(resU);
            rndPort = getRandomPort();
            std::cout << "got a request for conecting from ip = " << portIp.second << " prot = "<<PortS.port<< "sending response on port =" << serverPORT<<"rndPort:"<<rndPort<<std::endl;
            TCPRawSocketHandler::sendLongMessage(SERVER_IP,portIp.second,PortS.port,std::to_string(rndPort),serverPORT);
            
            std::thread newClient(&Communicator::handleNewClient, this,rndPort,portIp.second,PortS.port);
            newClient.detach();
        }
        catch (const std::exception&)
        {
            std::cout << "Client faild to connect." << std::endl;
        }
    }
}

void Communicator::handleNewClient(int srcPORT, const string &dstIP, int dstPORT) {

    JsonResponsePacketSerializer serializer;
    std::unique_lock<std::mutex> lock(m_mutex); // Lock mutex for thread safety
    lock.unlock();  // Unlocking here immediately after locking doesn't seem necessary, may want to lock only where needed

    RequestInfo reqInfo;
    int reqResult;
    SignupRequest SignupReq;
    SignupResponse SignupRes;
    std::vector<unsigned char> res;
    GetKeysResponse GetKeysRes;
    std::pair<std::vector<char> , string > portIp;
    bool isInDB = false;

    try {
        while (true) {
            char buffer[BUFFER_SIZE];
            size_t bytes_received;
            size_t dataSize;
            char* charArray = nullptr;

            // Receive data from client
            portIp = TCPRawSocketHandler::startServerOnOnePORT(SERVER_IP, srcPORT,dstPORT,dstIP);


            bytes_received = portIp.first.size();
            std::vector<unsigned char> ucharVector(portIp.first.begin(), portIp.first.end());

            reqInfo = IRequestHandler::makeInfo(ucharVector);  // This function could be dangerous if it modifies or invalidates data

            reqResult = requestHandl.handleRequest(reqInfo);
            /// set one more requset to get a secific key req 211 
            switch (reqResult) {
                case SignReq://206
                    SignupReq = requestHandl.handleSignRequest(reqInfo);
                    if (directorServer.insertPublicKey(SignupReq.m_publicKey, SignupReq.m_ip, SignupReq.m_port)) {
                        SignupRes.status = 1;
                        isInDB = true;
                        res = serializer.serializeResponse(SignupRes);
                    }
                    break;
                case GetKeysReq: //207
                    GetKeysRes = directorServer.getKeys(SignupReq.m_ip, SignupReq.m_port);
                    if (GetKeysRes.m_public_Keys.size() > 3) {
                        std::vector<Node> morePublicKeys;

                        // Create a split between the initial keys and the remaining ones
                        std::vector<Node> originalKeys = GetKeysRes.m_public_Keys;
                        GetKeysRes.m_public_Keys.resize(3);

                        // Add remaining keys to morePublicKeys
                        for (size_t i = 3; i < originalKeys.size(); ++i) {
                            morePublicKeys.push_back(originalKeys[i]);
                        }

                        // Mark that more data is available
                        GetKeysRes.isBig = true;
                        res = serializer.serializeResponse(GetKeysRes);
                        TCPRawSocketHandler::sendLongMessage(SERVER_IP, dstIP, dstPORT, std::string(res.begin(), res.end()));

                        // Receive next batch of data from client
                        portIp = TCPRawSocketHandler::startServerOnOnePORT(SERVER_IP, srcPORT);
                        bytes_received = portIp.first.size();
                        std::vector<unsigned char> ucharVector(portIp.first.begin(), portIp.first.end());
                        reqInfo = IRequestHandler::makeInfo(ucharVector);

                        reqResult = requestHandl.handleRequest(reqInfo);
                        if (!(reqResult == 208)) {
                            break;  // Exit if the request result is not 208
                        }

                        // Continue processing the next sets of keys if they exist
                        while (GetKeysRes.isBig) {
                            if (morePublicKeys.size() > 3) {
                                // Continue to process in chunks
                                std::vector<Node> originalKeys = morePublicKeys;
                                GetKeysRes.m_public_Keys = morePublicKeys;
                                GetKeysRes.m_public_Keys.resize(3);
                                morePublicKeys.clear();

                                for (size_t i = 3; i < originalKeys.size(); ++i) {
                                    morePublicKeys.push_back(originalKeys[i]);
                                }
                                GetKeysRes.isBig = true;
                                res = serializer.serializeResponse(GetKeysRes);
                                TCPRawSocketHandler::sendLongMessage(SERVER_IP, dstIP, dstPORT, std::string(res.begin(), res.end()));

                                // Receive next batch of data from client
                                portIp = TCPRawSocketHandler::startServerOnOnePORT(SERVER_IP, srcPORT);
                                bytes_received = portIp.first.size();
                                std::vector<unsigned char> ucharVector(portIp.first.begin(), portIp.first.end());
                                reqInfo = IRequestHandler::makeInfo(ucharVector);

                                reqResult = requestHandl.handleRequest(reqInfo);
                                if (!(reqResult == 208)) {
                                    break;
                                }
                            } else {
                                GetKeysRes.m_public_Keys = morePublicKeys;
                                GetKeysRes.isBig = false;
                                res = serializer.serializeResponse(GetKeysRes);
                            }
                        }
                    } else {
                        res = serializer.serializeResponse(GetKeysRes);
                    }
                    break;

                default:
                    break;
            }

            // Send final response to the client
            TCPRawSocketHandler::sendLongMessage(SERVER_IP, dstIP, dstPORT, std::string(res.begin(), res.end()),srcPORT);
        }
    }
    catch (const std::exception&) {
        if (isInDB) {
            directorServer.deletePublicKey(SignupReq.m_ip, SignupReq.m_port);
        }
    }
}


void Communicator::startCheckNodes()
{
    GetKeysResponse GetKeysRes;
    responseToDirector toDirector;
    std::string IpD;                // Destination IP address
    int PortD;
    ProtoPacket packetReq;
    JsonResponsePacketDeserializer deserializer;
    std::vector<unsigned char> ucharVector;
    RequestInfo reqInfo;
    std::pair<std::vector<char> , string > portIp;
    
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(15));
        GetKeysRes = directorServer.getKeys("0.0.0.0", 0); // to get all the keys
        for (Node& node : GetKeysRes.m_public_Keys)
        {
        size_t bytes_received;
            try
            {
                packetReq.o_head.typeInfo = 3;
                packetReq.o_head.IPdestination = node.IP;
                packetReq.o_head.PORTdestination = 1111;
                packetReq.o_head.layerCount = 0;
                time_t now;
                now = time(nullptr);

                 // Send the encrypted data to the destination server
                TCPRawSocketHandler::sendLongMessage(SERVER_IP, node.IP, node.port, std::string(packetReq.serialize().begin(), packetReq.serialize().end()));
                portIp = TCPRawSocketHandler::startServerOnOnePORT(SERVER_IP, packetReq.o_head.PORTdestination);
                bytes_received = portIp.first.size();
                std::vector<unsigned char> ucharVector(portIp.first.begin(), portIp.first.end());
                if (ucharVector.size() != 0)
                {
                    reqInfo = IRequestHandler::makeInfo(ucharVector);
                    toDirector = deserializer.deserializeToDirectorresponse(reqInfo.buffer);
                    if (toDirector.code != 1 || (difftime(toDirector.receivalTime, now)) > 1)
                    {
                        int i = 0;
                    }
                }


            }
            catch (const std::exception&)
            {

            }

        }


    }
   



}


// Handle client disconnection
void Communicator::handleClientDisconnection(int clientSocket) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_clients.find(clientSocket);
    if (it != m_clients.end()) {
        std::cout << "Client disconnected: " << clientSocket << std::endl;
        m_clients.erase(it); // Remove client from active clients
    }
}



std::string Communicator::getIPAddressFromName(const std::string& hostname) {
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





std::ostream& operator<<(std::ostream& os, const IPv4& ip) {
    os << (int)ip.b1 << "." << (int)ip.b2 << "." << (int)ip.b3 << "." << (int)ip.b4;
    return os;
}

IPv4 Communicator::getMyIP() {
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
