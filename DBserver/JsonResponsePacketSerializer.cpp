#include "JsonResponsePacketSerializer.h"


std::vector<unsigned char> JsonResponsePacketSerializer::serializeResponse(getAESKeyResponse a)
{
	std::string jsonStr;
	std::vector<unsigned char> bytes;
	json j;
	j["m_publicKey"] = a.m_publicKey;
	jsonStr = j.dump();
	j["ID"] = a.ID;
	jsonStr = j.dump();

	bytes = make(jsonStr, getAESKeyReq);
	return bytes;
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

std::vector<unsigned char> JsonResponsePacketSerializer::serializeResponse(PortResponse a)
{

	std::string jsonStr;
	std::vector<unsigned char> bytes;
	json j;

	j["port"] = a.port;
	jsonStr = j.dump();

	bytes = make(jsonStr, PortReq);
	return bytes;

}

std::vector<unsigned char> JsonResponsePacketSerializer::serializeResponse(GetKeysResponse a)
{

	std::string jsonStr;
	std::vector<unsigned char> bytes;
	json j;

	j["code"] = a.code;
	jsonStr = j.dump();

	bytes = make(jsonStr, GetKeysReq);
	return bytes;

}

std::vector<unsigned char> JsonResponsePacketSerializer::serializeResponse(SignupResponse a)
{
	json j;
	std::string jsonStr;
	std::vector<unsigned char> bytes;


	j["m_publicKey"] = a.m_publicKey;
	jsonStr = j.dump();
	j["m_port"] = a.m_port;
	jsonStr = j.dump();
	j["m_ip"] = a.m_ip;
	jsonStr = j.dump();
	bytes = make(jsonStr, SignReq);
	return bytes;
}

std::vector<unsigned char> JsonResponsePacketSerializer::serializeResponse(GetBigKeysResponse)
{
	json j;
	std::string jsonStr;
	std::vector<unsigned char> bytes;

	jsonStr = j.dump();
	bytes = make(jsonStr, GetBigKeysReq);
	return bytes;
}

std::vector<unsigned char> JsonResponsePacketSerializer::serializeResponse(responseToDirector a)
{
	json j;
	std::string jsonStr;
	std::vector<unsigned char> bytes;
	time_t now ;
	now = time(nullptr);
	j["code"] = a.code;
	jsonStr = j.dump();
	j["receivalTime"] = now;
	jsonStr = j.dump();
	j["m_ip"] = a.m_ip;
	jsonStr = j.dump();
	j["m_port"] = a.m_port;
	jsonStr = j.dump();
	bytes = make(jsonStr, DirecReq);
	return bytes;
}



std::vector<unsigned char> JsonResponsePacketSerializer::serializeResponse(nodeReqAES a)
{
    json j;
    std::string jsonStr;
    std::vector<unsigned char> bytes;

    // Create an empty json array for the key
    json keyArray = json::array();

    // Serialize the vector part of the key (first element of the key pair)
    for (const auto& val : a.key.first)
    {
        keyArray.push_back(val);
    }

    // Create the second array for the fixed-size array (second element of the key pair)
    json secondPart = json::array();
    for (size_t i = 0; i < BLOCK_SIZE; ++i)
    {
        secondPart.push_back(a.key.second[i]);
    }

    // Add both parts to the "key" field in the json object
    j["key"] = {keyArray, secondPart};

    // Serialize the object as a JSON string
    jsonStr = j.dump();

    // Convert the JSON string to bytes and return
    bytes = make(jsonStr, SignReq);
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




std::vector<unsigned char> JsonResponsePacketSerializer::make(std::vector<unsigned char> Response_json, int code)
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
