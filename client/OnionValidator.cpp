#include "OnionValidator.h"
#include <iostream>

bool OnionValidator::ValidateOnion(const ProtoPacket& packet) {
    // Check if the packet's layers are valid
    if (!ValidateLayer(packet)) {
        return false;
    }

    // Check if the encryption is valid
    if (!ValidateEncryption(packet)) {
        return false;
    }

    return true;
}

// Function to check if the packet was received (e.g., verify it includes all necessary data)
bool OnionValidator::CheckOnionReceived(const ProtoPacket& packet) {
    // Additional checks can be added here, such as verifying the validity of the packet's fields
    if (!ValidateOnion(packet)) {
        return false;
    }

    return true;
}

// Helper function to validate a single layer of the packet
bool OnionValidator::ValidateLayer(const ProtoPacket& packet) {
    // Add checks related to the packet's layers here
    if (packet.o_head.IPdestination != "127.0.0.1" && packet.o_head.layerCount < 1) {
        return false;
    }
    if (std::count(packet.o_head.IPdestination.begin(), packet.o_head.IPdestination.end(), '.') != 3) {
        return false;
    }
    if (packet.o_head.PORTdestination < 0 || packet.o_head.PORTdestination > 65535) {
        return false;
    }
    if (packet.o_head.lengthInfo < 0) {
        return false;
    }

    return true;
}

// Helper function to validate the encryption of the packet
bool OnionValidator::ValidateEncryption(const ProtoPacket& packet) {
    // Add encryption validation logic here
    return true;
}
