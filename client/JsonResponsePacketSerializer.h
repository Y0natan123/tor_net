#ifndef JSON_RESPONSE_PACKET_SERIALIZER_H
#define JSON_RESPONSE_PACKET_SERIALIZER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <ctime>
#include "json.hpp"
#include "IRequestHandler.h"

using json = nlohmann::json;

/////////////////////////////////////////

struct PortResponse
{
    int port;
} typedef PortResponse;

struct getAESKeyResponse
{
    std::pair<uint64_t, uint64_t> m_publicKey;
    int ID;
} typedef getAESKeyResponse;

struct SignupResponse
{
    std::pair<uint64_t, uint64_t> m_publicKey;
    std::string m_ip;
    int m_port;

} typedef SignupResponse;

struct ErrorResponse
{
    std::string message;
} typedef ErrorResponse;

struct GetKeysResponse
{
    int code = 1;
} typedef GetKeysResponse;

struct GetBigKeysResponse
{
    int code = 1;
} typedef GetBigKeysResponse;

struct responseToDirector
{
    int code = 1;
    time_t receivalTime;
    std::string m_ip;
    int m_port;
} typedef responseToDirector;

struct nodeReqAES
{
    std::pair<std::vector<uint8_t>, std::array<uint8_t, BLOCK_SIZE>> key;
} typedef nodeReqAES;

//////////////////////////////////////////

class JsonResponsePacketSerializer
{
public:
    static std::vector<unsigned char> serializeResponse(getAESKeyResponse);
    static std::vector<unsigned char> serializeResponse(PortResponse);
    static std::vector<unsigned char> serializeResponse(ErrorResponse);
    static std::vector<unsigned char> serializeResponse(GetKeysResponse);
    static std::vector<unsigned char> serializeResponse(SignupResponse);
    static std::vector<unsigned char> serializeResponse(GetBigKeysResponse);
    static std::vector<unsigned char> serializeResponse(responseToDirector);
    static std::vector<unsigned char> serializeResponse(nodeReqAES);
    static std::vector<unsigned char> make(std::vector<unsigned char> Response_json, int code);

private:
    static std::vector<unsigned char> make(std::string Response_json, int code);
};

#endif // JSON_RESPONSE_PACKET_SERIALIZER_H
