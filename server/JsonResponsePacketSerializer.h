#include <string>
#include <vector>
#include <map>
#include <ctime>

#include "json.hpp"
using json = nlohmann::json;
#define LoginReq 205
#define SignReq 206
#define GetKeysReq 207
#define ErorReq 100
#define Signout 101






/////////////////////////////////////////
struct LoginResponse
{
	unsigned int status;

};

struct SignupResponse
{
	unsigned int status;
};

struct ErrorResponse
{
	std::string message;
};


struct LogoutResponse
{
	unsigned int status;
};


// Definitions of structs
struct Node
{
	std::string IP;
	int port;
	std::pair<uint64_t, uint64_t> public_Key;

	bool operator==(const Node& other) const {
		return IP == other.IP && port == other.port;
	}
};


struct GetKeysResponse
{
	int id;
	bool isBig = false;
	std::vector<Node> m_public_Keys;
};






//////////////////////////////////////////


class JsonResponsePacketSerializer
{
public:

	static std::vector<unsigned char> serializeResponse(ErrorResponse);
	static std::vector<unsigned char> serializeResponse(LoginResponse);
	static std::vector<unsigned char> serializeResponse(SignupResponse);
	static std::vector<unsigned char> serializeResponse(LogoutResponse);
	static std::vector<unsigned char> serializeResponse(GetKeysResponse);

private:

	static std::vector<unsigned char> make(std::string Response_json, int code);
};
