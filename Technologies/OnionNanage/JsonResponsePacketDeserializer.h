


#ifndef JSON_RESPONSE_PACKET_DESERIALIZER_H
#define JSON_RESPONSE_PACKET_DESERIALIZER_H

#include <iostream>
#include <string>
#include <vector>
#include "json.hpp"


/////////////////////////
struct PortRequest
{
	int port;
};

struct LoginRequest
{
	unsigned int status;
	
};

struct SignupRequest
{
	unsigned int status;
};

// Definitions of structs
struct Node
{
	std::string IP;
	unsigned int port;
	std::pair<uint64_t, uint64_t> public_Key;
};

struct GetKeysRequest
{
	bool isBig;
	std::vector<Node> m_public_Keys;
};



//////////////////////////////
class JsonResponsePacketDeserializer
{
public:
	static PortRequest deserializePortRequest(std::vector<unsigned char> Buffer);
	static LoginRequest deserializeLoginRequest(std::vector<unsigned char> Buffer);
	static SignupRequest deserializeSignupRequest(std::vector<unsigned char> Buffer);
	static GetKeysRequest deserializeGetKeysRequest(std::vector<unsigned char> Buffer);
	
private:
	static std::string breakdown(std::vector<unsigned char> buffer);
};

#endif  // JSON_RESPONSE_PACKET_DESERIALIZER_H
