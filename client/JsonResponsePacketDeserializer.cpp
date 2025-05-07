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
RSAkeysRequest JsonResponsePacketDeserializer::deserializeRSAkeysRequest(std::vector<unsigned char> Buffer)
{
    RSAkeysRequest _RSAkeysRequest;
    json jObject;

    // Convert the buffer to a string
    std::string convertedString = breakdown(Buffer);
    
    try
    {
        // Parse the JSON object
        jObject = json::parse(convertedString);
        _RSAkeysRequest.ID = jObject["ID"];

        // Ensure the "key" field exists and is an array of two elements (for uint64_t pair)
        if (jObject.contains("m_publicKey") && jObject["m_publicKey"].is_array() && jObject["m_publicKey"].size() == 2)
        {
            // Deserialize the two elements of the "key" array into uint64_t values
            _RSAkeysRequest.key.first = jObject["m_publicKey"][0].get<uint64_t>();
            _RSAkeysRequest.key.second = jObject["m_publicKey"][1].get<uint64_t>();
        }
        else
        {
            throw std::runtime_error("Invalid or missing 'key' field in JSON, must be an array of two uint64_t values.");
        }
    }
    catch (const std::exception& ex)
    {
        // Handle JSON parsing or deserialization errors
        std::cerr << "Error deserializing AESkeysRequest: " << ex.what() << std::endl;
        throw;
    }

    jObject.clear();
    return _RSAkeysRequest;
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

std::string trimExcessBytes(const std::string& input)
{
    // Find the position of the last valid closing brace ('}')
    size_t lastBrace = input.rfind('}');
    if (lastBrace == std::string::npos)
    {
        throw std::runtime_error("Invalid JSON format: Missing closing brace.");
    }

    // Extract the valid part of the string up to the last brace
    std::string validJson = input.substr(0, lastBrace + 1);

    // Parse the JSON to ensure it is valid
    json parsedJson = json::parse(validJson);

    // Re-serialize the JSON to clean up formatting
    return parsedJson.dump();
}


AESkeysRequest JsonResponsePacketDeserializer::deserializeAESkeysRequest(std::vector<unsigned char> Buffer)
{
    AESkeysRequest _AESkeysRequest;
    json jObject;

    // Convert the buffer to a string
    std::string convertedString = breakdown(Buffer);
    convertedString =trimExcessBytes(convertedString);
    try
    {
       // Parse the JSON object
        jObject = json::parse(convertedString);

        // Ensure the "key" field exists
        if (jObject.contains("key") && jObject["key"].is_array() && jObject["key"].size() == 2)
        {
            // Deserialize the "first" part as a vector<uint8_t>
            for (const auto& val : jObject["key"][0])
            {
                _AESkeysRequest.key.first.push_back(static_cast<uint8_t>(val));
            }

            // Deserialize the "second" part as a std::array<uint8_t, BLOCK_SIZE>
            if (jObject["key"][1].is_array() && jObject["key"][1].size() == BLOCK_SIZE)
            {
                for (size_t i = 0; i < BLOCK_SIZE; ++i)
                {
                    _AESkeysRequest.key.second[i] = static_cast<uint8_t>(jObject["key"][1][i]);
                }
            }
            else
            {
                throw std::runtime_error("Invalid or missing 'second' field in 'key'.");
            }
        }
        else
        {
            throw std::runtime_error("Invalid or missing 'key' field in JSON.");
        }
    }
    catch (const std::exception& ex)
    {
        // Handle JSON parsing or deserialization errors
        std::cerr << "Error deserializing AESkeysRequest: " << ex.what() << std::endl;
        throw;
    }

    jObject.clear();
    return _AESkeysRequest;
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

    _getKeysRequest.id = jObject["id"];
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
