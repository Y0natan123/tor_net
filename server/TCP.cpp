#include "TCP.h"
#include <cstdlib>  // For rand() and srand()
#include <ctime>    // For time() to seed random number generator
#include <random>
/*function
input:
output:
explanation (minimal)*/
void TCPRawSocketHandler::sendLongMessage(const std::string &srcIP, const std::string &dstIP, int dstPORT, const std::string &message, int srcPort) {
    auto getRandomPort = [](int minPort = 1024, int maxPort = 65535) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(minPort, maxPort);
        return dis(gen);
    };

    int socketFd = createRawSocket(IPPROTO_TCP);
    if (srcPort == 0) {
        srcPort = getRandomPort();
    }
    std::cout<<"srcIP:"<<srcIP<<dstIP<<std::endl;
    bindSocket(socketFd, srcIP, srcPort);
    setupSocketOptions(socketFd);

    uint32_t seqNum = 0; // Initial sequence number
    uint32_t ackNum = 0; // Initial acknowledgment number
    int segmentSize = BUFFER_SIZE - 40; // Adjust for IP and TCP header sizes
    int segmentCount = (message.length() + segmentSize - 1) / segmentSize;
    bool ackReceived = false;

    // Set up the destination address structure for sending the message
    struct sockaddr_in destAddr = {};
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(dstPORT);
    destAddr.sin_addr.s_addr = inet_addr(dstIP.c_str());
    std::cout<<"send1"<<std::endl;

    // Send SYN to initiate connection
    sendSegment(socketFd, "", SYN, srcIP, dstIP, seqNum, ackNum, srcPort, dstPORT);
    //std::cout << "Sent SYN" << std::endl;
    ackReceived = waitForAck(socketFd, seqNum + 1, destAddr, srcPort, dstPORT);
    while (!ackReceived) {
        //std::cout << "Resending SYN" << std::endl;
        sendSegment(socketFd, "", SYN, srcIP, dstIP, seqNum, ackNum, srcPort, dstPORT);
        ackReceived = waitForAck(socketFd, seqNum + 1, destAddr, srcPort, dstPORT);
        //std::cout<<"wiat"<<std::endl;
    }
    seqNum++; // SYN consumes one sequence number
    ackReceived = false;
    std::cout<<"send2"<<std::endl;

    // Send data segments
    for (int i = 0; i < segmentCount; ++i) {
        std::string segment = message.substr(i * segmentSize, segmentSize);
        sendSegment(socketFd, segment, ACK, srcIP, dstIP, seqNum, ackNum, srcPort, dstPORT);
        //std::cout << "Sent data segment " << i + 1 << std::endl;
        ackReceived = waitForAck(socketFd, seqNum + segment.length(), destAddr, srcPort, dstPORT);
        while (!ackReceived) {
            //std::cout << "Resending data segment " << i + 1 << std::endl;
            sendSegment(socketFd, segment, ACK, srcIP, dstIP, seqNum, ackNum, srcPort, dstPORT);
            ackReceived = waitForAck(socketFd, seqNum + segment.length(), destAddr, srcPort, dstPORT);
        }
        seqNum += segment.length();
        ackReceived = false;
    }
    std::cout<<"send3"<<std::endl;
    // Send FIN to close the connection
    sendSegment(socketFd, "", FINACK, srcIP, dstIP, seqNum, ackNum, srcPort, dstPORT);
    //std::cout << "Sent FIN" << std::endl;
    ackReceived = waitForAck(socketFd, seqNum + 1, destAddr, srcPort, dstPORT);
    while (!ackReceived) {
        //std::cout << "Resending FIN" << std::endl;
        sendSegment(socketFd, "", FINACK, srcIP, dstIP, seqNum, ackNum, srcPort, dstPORT);
        ackReceived = waitForAck(socketFd, seqNum + 1, destAddr, srcPort, dstPORT);
    }

    close(socketFd);
}






// Implementation of startServer
std::pair<std::vector<char> , string > TCPRawSocketHandler::startServerOnOnePORT(const string &listenIP, int port , int destPort, std::string destIP) {
    std::pair<std::vector<char> , string > ret;
    int socketFd = createRawSocket(IPPROTO_TCP);
    bindSocket(socketFd,listenIP,port);
    setupSocketOptions(socketFd);
    TCPRawSocketHandler handler; // Create an instance of the class
    ret = handler.handleIncomingSegments(socketFd, listenIP, port ,destPort,destIP);
    close(socketFd);
    return ret;
}


std::pair<std::vector<char>, std::string> TCPRawSocketHandler::handleIncomingSegments(
    int socketFd, const std::string &listenIP, int port, int destPort, const std::string &destIP) {

    char buffer[BUFFER_SIZE];
    std::pair<std::vector<char>, std::string> ret;
    std::map<uint32_t, std::string> messageBuffer;
    uint32_t expectedSeqNum = 0;
    bool connectionEstablished = false;
    std::string senderIP = "";
    uint32_t senderISN = 0;

    while (true) {
        sockaddr_in srcAddr{};
        socklen_t srcLen = sizeof(srcAddr);

        ssize_t bytesRead = recvfrom(socketFd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&srcAddr, &srcLen);
        if (bytesRead > 0) {
            struct ip *IPheader = (struct ip *)buffer;
            struct tcphdr *TCPheader = (struct tcphdr *)(buffer + IPheader->ip_hl * 4);

            if (destPort != 0 && ntohs(TCPheader->th_sport) != destPort) {
                //std::cout << "Error: Unexpected source port: " << ntohs(TCPheader->th_sport)<< ", expected: " << destPort << std::endl;
                continue;
            }
            if (!destIP.empty() && destIP != inet_ntoa(IPheader->ip_src)) {
                //std::cout << "Error: Unexpected source IP: " << inet_ntoa(IPheader->ip_src)<< ", expected: " << destIP << std::endl;
                continue;
            }

            if (ntohs(TCPheader->th_dport) != port) {
                //std::cout << "Error: Unexpected destination port: " << ntohs(TCPheader->th_dport) << ", expected: " << port << std::endl;
                continue;
            }
            if (listenIP != inet_ntoa(IPheader->ip_dst)) {
                //std::cout << "Error: Unexpected destination IP: " << inet_ntoa(IPheader->ip_dst)<< ", expected: " << listenIP << std::endl;
                continue;
            }

            uint32_t seqNum = TCPheader->th_seq;
            uint32_t ackNum = TCPheader->th_ack;
            int payloadSize = bytesRead - (IPheader->ip_hl * 4 + TCPheader->th_off * 4);
            char *payload = buffer + IPheader->ip_hl * 4 + TCPheader->th_off * 4;

            if (TCPheader->th_flags & TH_SYN) {
                //std::cout << "Received SYN" << std::endl;
                senderISN = seqNum;
                expectedSeqNum = senderISN + 1;
                ackNum = 0;
                sendSegment(socketFd, "", SYNACK, inet_ntoa(IPheader->ip_dst), inet_ntoa(IPheader->ip_src),
                            ackNum, expectedSeqNum, ntohs(TCPheader->th_dport), ntohs(TCPheader->th_sport));
                connectionEstablished = true;
                continue;
            }

            if (TCPheader->th_flags & TH_FIN) {
                //std::cout << "Received FIN" << std::endl;
                expectedSeqNum = seqNum + 1;
                sendSegment(socketFd, "", FINACK, inet_ntoa(IPheader->ip_dst), inet_ntoa(IPheader->ip_src),
                            ackNum, expectedSeqNum, ntohs(TCPheader->th_dport), ntohs(TCPheader->th_sport));
                senderIP = inet_ntoa(IPheader->ip_src);
                break;
            }

            if (connectionEstablished && seqNum == expectedSeqNum && payloadSize > 0) {
                //std::cout << "Received data segment" << std::endl;
                std::string segmentData(payload, payloadSize);
                messageBuffer[seqNum] = segmentData;
                expectedSeqNum += payloadSize;
                sendSegment(socketFd, "", ACK, inet_ntoa(IPheader->ip_dst), inet_ntoa(IPheader->ip_src),
                            ackNum, expectedSeqNum, ntohs(TCPheader->th_dport), ntohs(TCPheader->th_sport));
            } else {
                //std::cout << "Unexpected segment or no payload. SeqNum: " << seqNum<< ", Expected: " << expectedSeqNum << std::endl;
            }
        }
    }

    std::string fullMessage;
    for (const auto &segment : messageBuffer) {
        fullMessage += segment.second;
    }
    std::vector<char> retData(fullMessage.begin(), fullMessage.end());
    retData.push_back('\0');
    ret.first = retData;
    ret.second = senderIP;
    return ret;
}



int TCPRawSocketHandler::createRawSocket(int protocol) {
    int socketFd = socket(AF_INET, SOCK_RAW, protocol);
    if (socketFd < 0) {
        perror("Failed to create raw socket");
        exit(EXIT_FAILURE);
    }
    return socketFd;
}

// Implementation of bindSocket
void TCPRawSocketHandler::bindSocket(int socketFd, const string &ip, int port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (bind(socketFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(socketFd);
        exit(EXIT_FAILURE);
    }
}
void TCPRawSocketHandler::setupSocketOptions(int socketFd) {
    int option = 1;
    if (setsockopt(socketFd, IPPROTO_IP, IP_HDRINCL, &option, sizeof(option)) < 0) {
        perror("ERROR setting socket options");
        exit(EXIT_FAILURE);
    }

}

void TCPRawSocketHandler::prepareIPHeader(struct ip *IPheader, const string &srcIP, const string &dstIP) {
    IPheader->ip_hl = 5;  // Header length (in 32-bit words)
    IPheader->ip_v = 4;   // IPv4
    IPheader->ip_tos = 0; // Type of service
    IPheader->ip_len = 0; // Will be set by kernel
    IPheader->ip_id = htonl(54321);
    IPheader->ip_off = 0;
    IPheader->ip_ttl = 255;  // Time to live
    IPheader->ip_p = IPPROTO_TCP; // Protocol
    IPheader->ip_sum = 0;  // Set to 0 before checksum calculation
    IPheader->ip_src.s_addr = inet_addr(srcIP.c_str());
    IPheader->ip_dst.s_addr = inet_addr(dstIP.c_str());
}
void TCPRawSocketHandler::prepareTCPHeader(struct tcphdr *TCPheader, int segmentNumber, uint32_t seqNum, uint32_t ackNum, int segmentType, int srcPORT, int dstPORT) {
    // Source and destination ports
    TCPheader->th_sport = htons(srcPORT);    // Source port
    TCPheader->th_dport = htons(dstPORT);    // Destination port

    // Sequence and acknowledgment numbers
    TCPheader->th_seq = seqNum;       // Sequence number
    TCPheader->th_ack = (segmentType == SYNACK || segmentType == FINACK || segmentType == ACK || segmentType == FIN) ? ackNum : 0;                 // Acknowledgment number for certain segment types

    // Header size: 5 means no options, so it's 20 bytes (5 * 4 bytes)
    TCPheader->th_off = 5;                  

    // Set the TCP flags based on segment type
    switch (segmentType) {
        case SYN:
            TCPheader->th_flags = TH_SYN;   // SYN flag
            break;
        case SYNACK:
            TCPheader->th_flags = TH_SYN | TH_ACK;  // SYN + ACK flags
            break;
        case ACK:
            TCPheader->th_flags = TH_ACK;   // ACK flag
            break;
        case FIN:
            TCPheader->th_flags = TH_FIN;  // FIN flag
            break;
        case FINACK:
            TCPheader->th_flags = TH_FIN | TH_ACK;  // FIN + ACK flags
            break;
        default:
            TCPheader->th_flags = 0;       // No flags set (should not happen) !!!!
            break;
    }

    // Set other fields
    TCPheader->th_win = htons(65535);      // Maximum window size
    TCPheader->th_sum = 0;                 // Checksum will be calculated later
    TCPheader->th_urp = 0;                 // Urgent pointer (unused in this implementation)
}


unsigned short TCPRawSocketHandler::calculateChecksum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--) {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<unsigned short>(~sum);
}

bool TCPRawSocketHandler::waitForAck(int socketFd, uint32_t expectedAckNum, struct sockaddr_in &destAddr , int dtsPort ,int srcPort  ) {
    fd_set readfds;
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;

    FD_ZERO(&readfds);
    FD_SET(socketFd, &readfds);

    int ret = select(socketFd + 1, &readfds, NULL, NULL, &timeout);
    if (ret == 0) {
        return false;
    }

    if (FD_ISSET(socketFd, &readfds)) {
        // Read the acknowledgment (simplified here)
        char buffer[BUFFER_SIZE];
        // Explicitly cast sizeof(destAddr) to socklen_t
        socklen_t addrLen = sizeof(destAddr);

        auto startTime = std::chrono::high_resolution_clock::now();

        while (true)
        {

            // Check elapsed time
            auto currentTime = std::chrono::high_resolution_clock::now();
            auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime);

            if (elapsedTime.count() >= 3) {
                break;
            }

        
            int bytesReceived = recvfrom(socketFd, buffer, sizeof(buffer), 0, (struct sockaddr *)&destAddr, &addrLen);
            if (bytesReceived > 0 ) {
                // Parse the acknowledgment
                struct tcphdr *TCPheader = (struct tcphdr *)(buffer + sizeof(struct ip));
                if (ntohs(TCPheader->th_dport) == dtsPort ) {//&& ntohs(TCPheader->th_sport) == 
                    if (srcPort != 0)
                    {
                        if (ntohs(TCPheader->th_sport) == srcPort)
                        {
                            if (TCPheader->th_ack == expectedAckNum)
                            {

                                return true;
                            }
                        }
                        
                    }
                    else if (TCPheader->th_ack == expectedAckNum)
                    {

                        return true;
                    }
                    
                    
                }
            }
        
        }
        
    }
    return false;
}

void TCPRawSocketHandler::sendSegment(int socketFd, const string &segment, int segmentNumber, const string &srcIP, const string &dstIP, uint32_t &seqNum, uint32_t &ackNum,int srcPORT, int dstPORT) {
    unsigned char packetBuf[BUFFER_SIZE] = {0};
    struct ip *IPheader = (struct ip *)packetBuf;
    struct tcphdr *TCPheader = (struct tcphdr *)(packetBuf + sizeof(struct ip));

    prepareIPHeader(IPheader, srcIP, dstIP);
    prepareTCPHeader(TCPheader, segmentNumber, seqNum, ackNum, segmentNumber,srcPORT,dstPORT);

    // Add the segment data after the TCP header
    memcpy(packetBuf + sizeof(struct ip) + sizeof(struct tcphdr), segment.c_str(), segment.length());

    // Calculate the checksum for IP and TCP headers
    IPheader->ip_sum = calculateChecksum((unsigned short *)packetBuf, sizeof(struct ip) / 2);
    TCPheader->th_sum = calculateChecksum((unsigned short *)(packetBuf + sizeof(struct ip)), sizeof(struct tcphdr) / 2);

    // Send the packet
    struct sockaddr_in destAddr = {};
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(TCPheader->th_sport);
    destAddr.sin_addr.s_addr = inet_addr(dstIP.c_str());

    int bufferSize = sizeof(struct ip) + sizeof(struct tcphdr) + segment.length();
    int bytesSent = sendto(socketFd, packetBuf, bufferSize, 0, (struct sockaddr *)&destAddr, sizeof(destAddr));

    if (bytesSent < bufferSize) {
        perror("ERROR sending segment");
        exit(EXIT_FAILURE);
    }
}