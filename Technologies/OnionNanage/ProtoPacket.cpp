// ProtoPacket.cpp
#include "ProtoPacket.h"



std::vector<uint8_t> ProtoPacket::serialize() const {
    std::vector<uint8_t> serializedPacket;

    // Serialize OnionHead
    // IPdestination: Copy as bytes (convert string to bytes or use placeholder logic here)
    for (char ch : o_head.IPdestination) {
        serializedPacket.push_back(static_cast<uint8_t>(ch));
    }
    serializedPacket.push_back(0); // Null-terminate the string for safety

    // PORTdestination: Serialize as 4 bytes
    serializedPacket.push_back((o_head.PORTdestination >> 24) & 0xFF);
    serializedPacket.push_back((o_head.PORTdestination >> 16) & 0xFF);
    serializedPacket.push_back((o_head.PORTdestination >> 8) & 0xFF);
    serializedPacket.push_back(o_head.PORTdestination & 0xFF);

    // layerCount: Serialize as 4 bytes
    serializedPacket.push_back((o_head.layerCount >> 24) & 0xFF);
    serializedPacket.push_back((o_head.layerCount >> 16) & 0xFF);
    serializedPacket.push_back((o_head.layerCount >> 8) & 0xFF);
    serializedPacket.push_back(o_head.layerCount & 0xFF);

    // lengthInfo: Serialize as 2 bytes
    serializedPacket.push_back((o_head.lengthInfo >> 8) & 0xFF);
    serializedPacket.push_back(o_head.lengthInfo & 0xFF);

    // typeInfo: Serialize as 1 byte
    serializedPacket.push_back(o_head.typeInfo);

    // Serialize OnionBody (encryptedData)
    serializedPacket.insert(serializedPacket.end(), o_body.encryptedData.begin(), o_body.encryptedData.end());

    return serializedPacket;
}




void ProtoPacket::deserialize(const std::vector<uint8_t>& data) {
    // Ensure data size is sufficient for deserialization
    if (data.size() < 15) { // Minimum size for OnionHead
        throw std::runtime_error("Insufficient data for deserialization.");
    }

    // Deserialize OnionHead
    size_t offset = 0;

    // Extract IPdestination (null-terminated string)
    std::string ip;
    while (data[offset] != 0) {
        ip.push_back(static_cast<char>(data[offset++]));
    }
    ++offset; // Skip the null terminator
    o_head.IPdestination = ip;

    // Extract PORTdestination (4 bytes)
    o_head.PORTdestination = (data[offset] << 24) | (data[offset + 1] << 16) |
        (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;

    // Extract layerCount (4 bytes)
    o_head.layerCount = (data[offset] << 24) | (data[offset + 1] << 16) |
        (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;

    // Extract lengthInfo (2 bytes)
    o_head.lengthInfo = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    // Extract typeInfo (1 byte)
    o_head.typeInfo = data[offset++];

    // Deserialize OnionBody (encryptedData)
    if (offset < data.size()) {
        o_body.encryptedData.assign(data.begin() + offset, data.end()-1);
    }
    else {
        o_body.encryptedData.clear(); // No data available
    }
}