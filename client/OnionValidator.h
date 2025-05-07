#ifndef ONIONVALIDATOR_H
#define ONIONVALIDATOR_H

#include "ProtoPacket.h"
class OnionValidator {
public:
    /**
     * @brief Validates the integrity of the Onion packet.
     *
     * @param packet The packet to validate.
     * @return true if the packet is valid, false otherwise.
     */
    bool ValidateOnion(const ProtoPacket& packet);

    /**
     * @brief Checks if the Onion packet has been properly received.
     *
     * @param packet The packet to check.
     * @return true if the packet is complete and valid, false otherwise.
     */
    bool CheckOnionReceived(const ProtoPacket& packet);

private:
    /**
     * @brief Validates a single layer of the packet.
     *
     * @param packet The packet to validate.
     * @return true if the layer is valid, false otherwise.
     */
    bool ValidateLayer(const ProtoPacket& packet);

    /**
     * @brief Validates the encryption within the packet.
     *
     * @param packet The packet to validate.
     * @return true if the encryption is valid, false otherwise.
     */
    bool ValidateEncryption(const ProtoPacket& packet);
};


#endif // ONIONVALIDATOR_H
