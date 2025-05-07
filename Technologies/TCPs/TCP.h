#include <sys/types.h>
#define __FAVOR_BSD
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <sys/time.h>
#include <thread>
#include <vector>
#include <map>
#include <utility>
using namespace std;

#define SYN 1
#define SYNACK 2
#define ACK 3
#define FINACK 4
#define FIN 5

class TCPRawSocketHandler {
public:
    static constexpr int BUFFER_SIZE = 45;
    static constexpr int TIMEOUT = 3;  // Timeout in seconds for retransmissions
    static constexpr int WINDOW_SIZE = 4;  // Maximum segments to send without acknowledgment
    static constexpr int MAX_RETRIES = 3;  // Max retries before giving up

    // Send message over raw socket with TCP-like behavior
    static void sendLongMessage(const string &srcIP, const string &dstIP, const int &dstPORT, const string &message);

    // Start a raw socket server
    static std::pair<char* , string> startServerOnOnePORT(const string &listenIP, int port);

    struct pseudo_header {
        uint32_t srcIP;       // Source IP address
        uint32_t dstIP;       // Destination IP address
        uint8_t placeholder;  // Always set to 0
        uint8_t protocol;     // Protocol (TCP = 6)
        uint16_t tcp_length;  // Length of the TCP segment (header + data)
    };

private:
    static int createRawSocket(int protocol);
    static void bindSocket(int socketFd, const string &ip, int port);
    static void setupSocketOptions(int socketFd);
    static void prepareIPHeader(struct ip *IPheader, const string &srcIP, const string &dstIP);
    static void prepareTCPHeader(struct tcphdr *TCPheader, int segmentNumber, uint32_t seqNum, uint32_t ackNum, int segmentType, int srcPORT, int dstPORT);
    static unsigned short calculateChecksum(unsigned short *buf, int nwords);
    static bool waitForAck(int socketFd, uint32_t expectedAckNum, struct sockaddr_in &destAddr , int port );
    static void sendSegment(int socketFd, const string &segment, int segmentNumber, const string &srcIP, const string &dstIP, uint32_t &seqNum, uint32_t &ackNum,int srcPORT, int dstPORT);
    std::pair<char* , string > handleIncomingSegments(int socketFd, const string &listenIP, int port);
};

/*function
input:
output:
explanation (minimal)*/
void TCPRawSocketHandler::sendLongMessage(const string &srcIP, const string &dstIP, const int &dstPORT, const string &message) {
    int socketFd = createRawSocket(IPPROTO_TCP);
    bindSocket(socketFd,dstIP,12345);
    setupSocketOptions(socketFd);

    uint32_t seqNum = 0;
    uint32_t ackNum = 0;
    int segmentCount = (message.length() + BUFFER_SIZE- 40 - 1) / (BUFFER_SIZE -40);
    bool ackReceived  = false;
    // Set up the destination address structure for sending the message
    struct sockaddr_in destAddr = {};
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(dstPORT);         // Destination port
    destAddr.sin_addr.s_addr = inet_addr(dstIP.c_str()); // Destination IP address

    // Send SYN to initiate connection
    sendSegment(socketFd, "", SYN, srcIP, dstIP, seqNum,ackNum,12345,dstPORT);  // SYN with no data
    ackReceived = waitForAck(socketFd, seqNum, destAddr ,12345 );
    while (1 - ackReceived) {

        sendSegment(socketFd, "", SYN, srcIP, dstIP, seqNum,ackNum,12345,dstPORT);  // Retry SYN if no ACK
        ackReceived = waitForAck(socketFd, seqNum , destAddr ,12345);
    }
    ackReceived  = false;
    if (segmentCount >= 1)
    {
        for (int i = 0; i < segmentCount; ++i) {
            string segment = message.substr(i * (BUFFER_SIZE -40), BUFFER_SIZE - 40);
            seqNum += segment.length();  // Increment sequence number after sending segment
            sendSegment(socketFd, segment, ACK, srcIP, dstIP, seqNum,ackNum,12345,dstPORT);
           
            // Wait for acknowledgment of the segment
            ackReceived = waitForAck(socketFd, seqNum, destAddr ,12345);
            while (!ackReceived) {
                cout << "Timeout, retrying segment " << i + 1 << endl;
                sendSegment(socketFd, segment, ACK, srcIP, dstIP, seqNum,ackNum,12345,dstPORT);  // Retry segment
                ackReceived = waitForAck(socketFd, seqNum, destAddr ,12345);
            }
            
            ackReceived  = false;
        }
    }
    fd_set readfds;
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;

    auto startTime = std::chrono::high_resolution_clock::now();

       
        
    // Send FIN to close the connection
    sendSegment(socketFd, "", FINACK, srcIP, dstIP, seqNum,ackNum,12345,dstPORT);  // FIN with no data
    ackReceived = waitForAck(socketFd, seqNum, destAddr ,12345);
    while (!ackReceived) {
        // Check elapsed time
        auto currentTime = std::chrono::high_resolution_clock::now();
        auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime);
        if (elapsedTime.count() >= 25) {
            std::cout << "Time is up! Stopping the loop." << std::endl;
            break;
        }
        sendSegment(socketFd, "", FINACK, srcIP, dstIP, seqNum,ackNum,12345,dstPORT);  // Retry FIN if no ACK
        ackReceived = waitForAck(socketFd, seqNum, destAddr ,12345);
    }

    close(socketFd);
}


// Implementation of startServer
std::pair<char* , string > TCPRawSocketHandler::startServerOnOnePORT(const string &listenIP, int port) {
    std::pair<char* , string > ret;
    int socketFd = createRawSocket(IPPROTO_TCP);
    bindSocket(socketFd,listenIP,54321);
    setupSocketOptions(socketFd);
    TCPRawSocketHandler handler; // Create an instance of the class
    ret = handler.handleIncomingSegments(socketFd, listenIP, port);
    close(socketFd);
    return ret;
}

std::pair<char*, string > TCPRawSocketHandler::handleIncomingSegments(int socketFd, const string &listenIP, int port) {
    char buffer[BUFFER_SIZE];
    std::pair<char* , string > ret;
    map<uint32_t, string> messageBuffer;  // Buffer to store segments by sequence number
    uint32_t expectedSeqNum = 0;
    bool ackReceived  = false;
    char* retData = nullptr;
    string ipD = "";
    while (true) {
        sockaddr_in srcAddr{};
        socklen_t srcLen = sizeof(srcAddr);
        ssize_t bytesRead = recvfrom(socketFd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&srcAddr, &srcLen);
        string segment =""; 
        if (bytesRead > 0) {
            struct ip *IPheader = (struct ip *)buffer;
            struct tcphdr *TCPheader = (struct tcphdr *)(buffer + IPheader->ip_hl * 4);

            // Verify destination port
            if (ntohs(TCPheader->th_dport) != port) {
                continue;
            }
            
            uint32_t seqNum = TCPheader->th_seq;
            uint32_t ackNum = TCPheader->th_ack;
            int payloadSize = bytesRead - (IPheader->ip_hl * 4 + TCPheader->th_off * 4);



            // Process SYN flag
            if (TCPheader->th_flags & TH_SYN) {
                seqNum = seqNum+ payloadSize;
                sendSegment(socketFd,"",SYNACK,inet_ntoa(IPheader->ip_dst),inet_ntoa(IPheader->ip_src),ackNum,seqNum,ntohs(TCPheader->th_dport),ntohs(TCPheader->th_sport));
                
                continue;
            }

            // Process FIN flag
            if (TCPheader->th_flags & TH_FIN) {
                seqNum = seqNum+ payloadSize;
                // Prepare FIN-ACK
                sendSegment(socketFd,"",FIN,inet_ntoa(IPheader->ip_dst),inet_ntoa(IPheader->ip_src),ackNum,seqNum,ntohs(TCPheader->th_dport),ntohs(TCPheader->th_sport));
                ipD = inet_ntoa(IPheader->ip_dst);

                break;
            }

            // Process incoming data
            if (ackNum == expectedSeqNum && payloadSize > 0) {
                char *payload = buffer + IPheader->ip_hl * 4 + TCPheader->th_off * 4;
                string segmentData(payload, payloadSize);
                messageBuffer[seqNum] = segmentData;

                cout << "Received segment: " << segmentData << endl;
                seqNum = seqNum+ payloadSize;
                sendSegment(socketFd,"",ACK,inet_ntoa(IPheader->ip_dst),inet_ntoa(IPheader->ip_src),ackNum,seqNum,ntohs(TCPheader->th_dport),ntohs(TCPheader->th_sport));
                expectedSeqNum += payloadSize;
            }
            else if (ackNum == (expectedSeqNum - payloadSize) && payloadSize > 0) {
                char *payload = buffer + IPheader->ip_hl * 4 + TCPheader->th_off * 4;
                string segmentData(payload, payloadSize);
                messageBuffer[seqNum] = segmentData;

                sendSegment(socketFd,"",ACK,inet_ntoa(IPheader->ip_dst),inet_ntoa(IPheader->ip_src),ackNum,seqNum,ntohs(TCPheader->th_dport),ntohs(TCPheader->th_sport));
            }
            else {
                cout << "Unexpected segment or no payload. SeqNum: " << seqNum << ", Expected: " << expectedSeqNum << endl;
            }
        }
    }

    // Reconstruct the complete message
    string fullMessage;
    for (const auto &segment : messageBuffer) {
        fullMessage += segment.second;
    }
    std::strcpy(retData, fullMessage.c_str());
    ret.first = retData;
    ret.second = ipD;
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
    cout << "Socket options configured." << endl;
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

bool TCPRawSocketHandler::waitForAck(int socketFd, uint32_t expectedAckNum, struct sockaddr_in &destAddr , int port) {
    fd_set readfds;
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;

    FD_ZERO(&readfds);
    FD_SET(socketFd, &readfds);

    int ret = select(socketFd + 1, &readfds, NULL, NULL, &timeout);
    if (ret == 0) {
        cout << "Timeout reached, no ACK received." << endl;
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

            if (elapsedTime.count() >= 1) {
                std::cout << "Time is up! Stopping the loop." << std::endl;
                break;
            }

        
            int bytesReceived = recvfrom(socketFd, buffer, sizeof(buffer), 0, (struct sockaddr *)&destAddr, &addrLen);
            if (bytesReceived > 0 ) {
                // Parse the acknowledgment
                struct tcphdr *TCPheader = (struct tcphdr *)(buffer + sizeof(struct ip));
                if (ntohs(TCPheader->th_dport) == port) {
                    if (TCPheader->th_ack == expectedAckNum)
                    {
                        cout << "ACK received for sequence number " << expectedAckNum + 1 << endl;
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

    cout << "Segment " << segmentNumber << " sent successfully! Sent bytes: " << bytesSent << endl;


}
