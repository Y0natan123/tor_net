#include "JsonResponsePacketDeserializer.h"
#include "json.hpp"
using json = nlohmann::json;

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



LoginRequest JsonResponsePacketDeserializer::deserializeLoginRequest(std::vector<unsigned char> Buffer)
{
    LoginRequest _loginRequest;
    json jObject;

    std::string convertedString = breakdown(Buffer);
    jObject = json::parse(convertedString);
    _loginRequest.username = jObject["username"];
    _loginRequest.password = jObject["password"];
    jObject.clear();
    return _loginRequest;
}

SignupRequest JsonResponsePacketDeserializer::deserializeSignupRequest(std::vector<unsigned char> Buffer)
{
    SignupRequest _signupRequest;

    // Convert buffer to a string
    std::string convertedString(Buffer.begin(), Buffer.end());

    try {
        // Parse JSON from the converted string
        json jObject = json::parse(convertedString);

        // Convert the byte arrays to uint64_t values
        _signupRequest.m_publicKey.first = jObject["m_publicKey"][0];
        _signupRequest.m_publicKey.second = jObject["m_publicKey"][1];
        _signupRequest.m_ip = jObject["m_ip"].get<std::string>();
        _signupRequest.m_port = jObject["m_port"].get<int>();

    }
    catch (const json::exception& e) {
        throw std::runtime_error("JSON parsing error: " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        throw std::runtime_error("General error: " + std::string(e.what()));
    }

    return _signupRequest;
}

responseToDirector JsonResponsePacketDeserializer::deserializeToDirectorresponse(std::vector<unsigned char> Buffer)
{
    responseToDirector _responseToDirector;
    json jObject;

    std::string convertedString = breakdown(Buffer);
    jObject = json::parse(convertedString);
    _responseToDirector.code = jObject["code"];
    _responseToDirector.receivalTime = jObject["code"];
    _responseToDirector.m_ip = jObject["m_ip"];
    _responseToDirector.m_port = jObject["m_port"];
    jObject.clear();
    return _responseToDirector;
}

GetSpecificKeyRequest JsonResponsePacketDeserializer::deserializeGetSpecificKeyRequest(std::vector<unsigned char> Buffer)
{
    GetSpecificKeyRequest request;
    json jObject;

    std::string convertedString = breakdown(Buffer);
    jObject = json::parse(convertedString);
    
    request.ip = jObject["ip"].get<std::string>();
    request.port = jObject["port"].get<int>();
    
    jObject.clear();
    return request;
}

std::string JsonResponsePacketDeserializer::breakdown(std::vector<unsigned char> buffer)
{
    std::string result;

    for (size_t i = 5; i < buffer.size(); i ++) {


        result.push_back(static_cast<char>(buffer[i]));
    }

    return result;
}
