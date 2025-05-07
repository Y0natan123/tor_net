// ProtoPacket.h
#ifndef PROTO_PACKET_H
#define PROTO_PACKET_H

#include <vector>
#include <cstdint>
#include "json.hpp"

// Represents the next node's details in the Onion Routing process.
struct NextNode {
    uint32_t IPdestination;             // Destination IP address.
    uint32_t PORTdestination;           // Destination port.
    std::vector<uint8_t> encryptedData; // Encrypted data for this node.
};

// Represents the header of an Onion packet.
struct OnionHead {
    std::string IPdestination;          // Target IP address of the packet.
    uint32_t PORTdestination;           // Target port of the packet.
    uint32_t layerCount;                // Number of encryption layers remaining.
    uint16_t lengthInfo;                // Length information of the packet.
    uint8_t typeInfo;                   // Type information for protocol identification.
    int id;
};

// Represents the body of an Onion packet.
struct OnionBody {
    std::vector<uint8_t> encryptedData; // Encrypted data payload.
};

// Represents an Onion Routing protocol packet.
class ProtoPacket {
public:
    OnionHead o_head;                   // Packet header.
    OnionBody o_body;                   // Packet body.

    /**
     * @brief Serializes the packet into a byte vector for transmission.
     *
     * @return Serialized byte vector.
     */
    std::vector<uint8_t> serialize() const;

    /**
     * @brief Deserializes a byte vector into a ProtoPacket object.
     *
     * @param data Byte vector representing the serialized packet.
     */
    void deserialize(const std::vector<uint8_t>& data);
};


#endif // PROTO_PACKET_H
