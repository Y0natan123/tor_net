#include <iostream>
#include <vector>
#include "json.hpp"
#include <string>

/////////////////////////
struct PortRequest
{
	int port;
};

struct LoginRequest
{
	std::string username;
	std::string password;
};

struct SignupRequest
{
	std::pair<uint64_t, uint64_t> m_publicKey;
	std::string m_ip;
	int m_port;
};

struct GetSpecificKeyRequest {
	std::string ip;
	int port;
};


struct responseToDirector
{
	int code = 1;
	time_t receivalTime;
	std::string m_ip;
	int m_port;
}typedef responseToDirector;


//////////////////////////////
class JsonResponsePacketDeserializer
{
public:
	static PortRequest deserializePortRequest(std::vector<unsigned char> Buffer);
	static LoginRequest deserializeLoginRequest(std::vector<unsigned char> Buffer);
	static SignupRequest deserializeSignupRequest(std::vector<unsigned char> Buffer);
	static responseToDirector deserializeToDirectorresponse(std::vector<unsigned char> Buffer);
	static GetSpecificKeyRequest deserializeGetSpecificKeyRequest(std::vector<unsigned char> Buffer);
private:
	static std::string breakdown(std::vector<unsigned char> buffer);
};

