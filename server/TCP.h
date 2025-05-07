#ifndef TCP_H
#define TCP_H

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
    static constexpr int BUFFER_SIZE = 4096;
    static constexpr int TIMEOUT = 0.1;  // Timeout in seconds for retransmissions
    static constexpr int WINDOW_SIZE = 4;  // Maximum segments to send without acknowledgment
    static constexpr int MAX_RETRIES = 3;  // Max retries before giving up

    // Send message over raw socket with TCP-like behavior
    static void sendLongMessage(const std::string &srcIP, const std::string &dstIP, int dstPORT, const std::string &message, int srcPort = 0);

    // Start a raw socket server
    static std::pair<std::vector<char> , string> startServerOnOnePORT(const string &listenIP, int port, int destPort = 0 , std::string destIP = "");
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
    static bool waitForAck(int socketFd, uint32_t expectedAckNum, struct sockaddr_in &destAddr , int dstPort ,int srcPort = 0);
    static void sendSegment(int socketFd, const string &segment, int segmentNumber, const string &srcIP, const string &dstIP, uint32_t &seqNum, uint32_t &ackNum,int srcPORT, int dstPORT);
    std::pair<std::vector<char> , string > handleIncomingSegments(int socketFd, const std::string &listenIP, int port, int destPort, const std::string &destIP = "");
};

#endif // TCP_H