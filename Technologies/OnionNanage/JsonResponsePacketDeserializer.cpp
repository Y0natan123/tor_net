#include "JsonResponsePacketDeserializer.h"
#include "json.hpp"
using json = nlohmann::json;

//LoginRequest JsonResponsePacketDeserializer::deserializeLoginRequest(std::vector<unsigned char> Buffer)
//{
//    LoginRequest _loginRequest;
//    json jObject;
//
//    std::string convertedString = breakdown(Buffer);
//    jObject = json::parse(convertedString);
//    _loginRequest.username = jObject["username"];
//    _loginRequest.password = jObject["password"];
//    jObject.clear();
//    return _loginRequest;
//}
uint64_t vectorToUint64(const std::vector<unsigned char>& byteVec) {
    if (byteVec.size() != sizeof(uint64_t)) {
        throw std::invalid_argument("Byte vector size must be 8 bytes to convert to uint64_t.");
    }

    uint64_t result = 0;
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        result |= static_cast<uint64_t>(byteVec[i]) << (8 * (sizeof(uint64_t) - 1 - i));
    }
    return result;
}

PortRequest JsonResponsePacketDeserializer::deserializePortRequest(std::vector<unsigned char> Buffer)
{
    PortRequest _portRequest;
    json jObject;

    std::string convertedString = breakdown(Buffer);
    jObject = json::parse(convertedString);
    _portRequest.port = jObject["port"];

    jObject.clear();
    return _portRequest;
}



SignupRequest JsonResponsePacketDeserializer::deserializeSignupRequest(std::vector<unsigned char> Buffer)
{
    SignupRequest _signupRequest;
    json jObject;

    std::string convertedString = breakdown(Buffer);
    jObject = json::parse(convertedString);
    _signupRequest.status = jObject["status"];
    return _signupRequest;
}

GetKeysRequest JsonResponsePacketDeserializer::deserializeGetKeysRequest(std::vector<unsigned char> Buffer)
{
    GetKeysRequest _getKeysRequest;
    json jObject;

    // Convert the buffer to a string
    std::string convertedString = breakdown(Buffer);

    // Parse the string as JSON
    jObject = json::parse(convertedString);

    // Extract the status (isBig)
    _getKeysRequest.isBig = jObject["isBig"].get<bool>();

    // Extract the array of public keys
    for (const auto& keyObj : jObject["public_keys"])
    {
        Node currentNode;
        currentNode.IP = keyObj["IP"].get<std::string>();
        currentNode.port = keyObj["port"].get<unsigned int>();

        // Convert the public key from JSON array to std::vector<unsigned char>
        currentNode.public_Key.first = keyObj["public_Key"][0];
        currentNode.public_Key.second = keyObj["public_Key"][1];


        // Add the pair of public key and node to the vector
        _getKeysRequest.m_public_Keys.emplace_back(currentNode);
    }

    return _getKeysRequest;
}


std::string JsonResponsePacketDeserializer::breakdown(std::vector<unsigned char> buffer)
{
    std::string result;

    for (size_t i = 0; i < buffer.size(); i ++) {


        result.push_back(static_cast<char>(buffer[i]));
    }

    return result;
}
