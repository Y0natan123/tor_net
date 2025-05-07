#ifndef ONION_MANAGER_H
#define ONION_MANAGER_H

#include "ProtoPacket.h"
#include "RSA.h"
#include "AES.h"
#include "JsonResponsePacketDeserializer.h"
#include <vector>

// OnionManager class handles key generation and encryption/decryption of layers in onion routing
class OnionManager {
private:
    std::pair<uint64_t, uint64_t> m_publicKey;  // Public key used for encryption
    std::pair<uint64_t, uint64_t> m_secretKey;  // Secret key used for decryption

public:
    // Key management

    /**
     * @brief Generates a new keypair (public and secret keys) for encryption and decryption.
     */
    void GenerateNewKeypair();

    // Encryption and decryption functions

    /**
     * @brief Encrypts a single layer of data.
     *
     * @param data The original data to be encrypted.
     * @return std::vector<uint8_t> The encrypted data for the layer.
     */
    std::vector<uint8_t> EncryptLayer(const std::vector<uint8_t>& data);

    /**
     * @brief Prepares an onion-encrypted message by wrapping data through multiple nodes.
     *
     * @param nodes The route of nodes to encrypt the data for.
     * @param originalData The original data to be encrypted into the onion layers.
     * @return std::pair<std::vector<uint8_t>, Node> A pair containing the encrypted onion message and the next node.
     */
    std::pair<std::vector<uint8_t>, Node> PrepareOnion(
        const std::vector<Node>& nodes, 
        const std::vector<uint8_t>& originalData, 
        std::vector<AESkeysRequest*> m_AES_keys,
        int pakageId
        );
    /**
     * @brief Encrypts data using the public key of a specified node.
     *
     * @param node The node whose public key will be used for encryption.
     * @param data The data to encrypt.
     * @param nonce A nonce to ensure encryption randomness.
     * @return std::vector<uint8_t> The encrypted data.
     */
    std::vector<uint8_t> EncryptWithPublicKey(const Node& node, const std::vector<uint8_t>& data);

    /**
     * @brief Encrypts data using the public key of a specified node.
     *
     * @param public_Key The public key of the node.
     * @param data The data to encrypt.
     * @return std::vector<uint8_t> The encrypted data.
     */
    std::vector<uint8_t> EncryptWithPublicKey(const std::pair<uint64_t, uint64_t>& public_Key, const std::vector<uint8_t>& data);

    /**
     * @brief Decrypts a single layer of data.
     *
     * @param encryptedData The encrypted data of a layer.
     * @return std::vector<uint8_t> The decrypted data of the layer.
     */
    std::vector<uint8_t> DecryptLayer(const std::vector<uint8_t>& encryptedData);

    // Getters

    /**
     * @brief Retrieves the public key of this OnionManager.
     *
     * @return const std::pair<uint64_t, uint64_t>& The public key.
     */
    const std::pair<uint64_t, uint64_t>& GetPublicKey() const;
};

#endif // ONION_MANAGER_H
