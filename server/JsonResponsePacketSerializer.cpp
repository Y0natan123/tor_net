#include "JsonResponsePacketSerializer.h"
#include "json.hpp"
using json = nlohmann::json;
// Convert `Node` to JSON
// Add this at the top of the file or in a relevant header file
void to_json(nlohmann::json& j, const Node& node) {
	j = nlohmann::json{
		{"IP", node.IP},
		{"port", node.port},
		{"public_Key", node.public_Key}
	};
}
std::vector<unsigned char> JsonResponsePacketSerializer::serializeResponse(ErrorResponse a)
{
	std::string jsonStr;
	std::vector<unsigned char> bytes;
	json j;
	
	j["message"] = a.message;
	jsonStr = j.dump();

	bytes = make(jsonStr, ErorReq);
	return bytes;
}



std::vector<unsigned char> JsonResponsePacketSerializer::serializeResponse(LoginResponse a)
{
	std::string jsonStr;
	std::vector<unsigned char> bytes;
	json j;
	
	j["status"] = a.status;
	jsonStr = j.dump();

	bytes = make(jsonStr, LoginReq);
	return bytes;
}

std::vector<unsigned char> JsonResponsePacketSerializer::serializeResponse(SignupResponse a)
{
	json j;
	std::string jsonStr;
	std::vector<unsigned char> bytes;


	j["status"] = a.status;
	jsonStr = j.dump();


	bytes = make(jsonStr, SignReq);
	return bytes;
}


std::vector<unsigned char> JsonResponsePacketSerializer::serializeResponse(LogoutResponse a)
{
	json j;
	std::string jsonStr;
	std::vector<unsigned char> bytes;


	j["status"] = a.status;
	jsonStr = j.dump();


	bytes = make(jsonStr, SignReq);
	return bytes;
}
std::vector<unsigned char> JsonResponsePacketSerializer::serializeResponse(GetKeysResponse a)
{
	nlohmann::json j;
	std::vector<unsigned char> bytes;
	// Add `isBig` to the JSON object
	j["isBig"] = a.isBig;
	
	j["id"] = a.id; // This now works because of the custom `to_json`
	// Serialize the `m_public_Keys` vector
	j["public_keys"] = a.m_public_Keys; // This now works because of the custom `to_json`

	// Convert the JSON object to string
	std::string jsonStr = j.dump();
	bytes = make(jsonStr, 207);

	// Convert the JSON string to a vector of unsigned char
	return bytes;
}





std::vector<unsigned char> JsonResponsePacketSerializer::make(std::string Response_json, int code)
{
	std::vector<unsigned char> ret;
	std::vector<unsigned char> code_char;
	std::vector<unsigned char> sizeMsg_char;

	unsigned int code_ret = '0';
	unsigned int sizeMsg = '0';

	sizeMsg = Response_json.size();
	code_ret = code;

	for (size_t i = 0; i < sizeof(unsigned char); ++i) {
		// Extract each byte and push it to the vector
		unsigned char byte = (code_ret >> (i * 8)) & 0xFF;
		code_char.push_back(byte);
	}


	for (size_t i = 0; i < sizeof(unsigned int); ++i) {
		// Extract each byte and push it to the vector
		unsigned char byte2 = (sizeMsg >> (i * 8)) & 0xFF;
		sizeMsg_char.push_back(byte2);
	}

	//[code]->>
	ret.insert(ret.begin(), code_char.begin(), code_char.end());
	//[code,size]->>
	ret.insert(ret.end(), sizeMsg_char.begin(), sizeMsg_char.end());\
	//[code,size,msg]
	ret.insert(ret.end(), Response_json.begin(), Response_json.end());


	return ret;
}






