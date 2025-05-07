#include "OnionManager.h"


std::vector<uint8_t> intToBytes(int value) {
    std::vector<uint8_t> bytes(sizeof(int));
    std::memcpy(bytes.data(), &value, sizeof(int));
    return bytes;
}
void OnionManager::GenerateNewKeypair() 
{
    std::pair<std::pair<uint64_t, uint64_t>, std::pair<uint64_t, uint64_t>> publicAndPrivetKeys = AsymmetricEncryption::GenerateKeypair();
    m_publicKey = publicAndPrivetKeys.first;
    m_secretKey = publicAndPrivetKeys.second;
}

std::vector<uint8_t> OnionManager::EncryptLayer(const std::vector<uint8_t>& data) {
    // Step 1: Convert the data to a string (if needed) for encryption
    std::string dataStr(data.begin(), data.end());
    
    // Step 2: Encrypt the data using the public key of the OnionManager
    std::vector<uint64_t> encryptedData = AsymmetricEncryption::Encrypt(dataStr, m_publicKey);

    // Step 3: Convert encrypted data to a vector of uint8_t for compatibility
    std::vector<uint8_t> encryptedBytes;
    for (const uint64_t& block : encryptedData) {
        // Convert each uint64_t block to a byte array and append to the result
        for (size_t i = 0; i < sizeof(uint64_t); ++i) {
            encryptedBytes.push_back(static_cast<uint8_t>((block >> (i * 8)) & 0xFF));
        }
    }

    // Step 4: Return the encrypted byte vector
    return encryptedBytes;
}

std::vector<uint8_t> OnionManager::DecryptLayer(const std::vector<uint8_t>& encryptedData) {
    // Step 1: Convert the encrypted data from bytes (uint8_t) back to uint64_t blocks
    std::vector<uint64_t> encryptedBlocks;
    for (size_t i = 0; i < encryptedData.size(); i += sizeof(uint64_t)) {
        uint64_t block = 0;
        for (size_t j = 0; j < sizeof(uint64_t); ++j) {
            block |= (static_cast<uint64_t>(encryptedData[i + j]) << (j * 8));
        }
        encryptedBlocks.push_back(block);
    }

    // Step 2: Decrypt the data using the private key of the OnionManager
    std::string decryptedData = AsymmetricEncryption::Decrypt(encryptedBlocks, m_secretKey);

    // Step 3: Convert the decrypted string back to std::vector<uint8_t>
    std::vector<uint8_t> decryptedBytes(decryptedData.begin(), decryptedData.end());

    // Step 4: Return the decrypted byte vector
    return decryptedBytes;
}

std::pair<std::vector<uint8_t>, Node> OnionManager::PrepareOnion(
    const std::vector<Node>& nodes, 
    const std::vector<uint8_t>& originalData, 
    std::vector<AESkeysRequest*> m_AES_keys,
    int pakageId)
{
    if (nodes.empty()) {
        throw std::runtime_error("Node list is empty.");
    }

    if (nodes.size() != m_AES_keys.size()) {
        throw std::runtime_error("Mismatch between nodes and AES keys.");
    }

    std::vector<uint8_t> encryptedData = originalData; // Start with the original data

    // Iterate over the nodes in reverse order
    for (size_t i = 0; i < nodes.size(); ++i) {
        std::vector<uint8_t> pakageIdUnit8 = intToBytes(pakageId);
        const Node& currentNode = nodes[nodes.size() - 1 - i]; // Current node (reverse order)
        const Node& nextNode = (i > 0) ? nodes[nodes.size() - i] : Node{ "", 0, std::pair<uint64_t, uint64_t>() }; // Next node

        // Prepare the ProtoPacket
        ProtoPacket packet;
        if (i == 0) {
            // Last layer: destination is localhost
            packet.o_head.IPdestination = "127.0.0.1";
            packet.o_head.PORTdestination = 0;
        } else {
            // Intermediate layer: destination is the next node
            packet.o_head.IPdestination = nextNode.IP;
            packet.o_head.PORTdestination = nextNode.port;
        }

        packet.o_head.layerCount = nodes.size();
        packet.o_head.lengthInfo = encryptedData.size();
        packet.o_head.typeInfo = (i == 0) ? 0x02 : 0x01; // Type info: 0x02 for last layer

        // Add the encrypted data to the packet body
        packet.o_body.encryptedData = encryptedData;

        // Serialize the packet
        std::vector<uint8_t> serializedPacket = packet.serialize();

        // Retrieve the AES key and IV from m_AES_keys
        AESkeysRequest* keyRequest = m_AES_keys[nodes.size() - 1 - i]; // Match the current node
        std::pair<std::vector<uint8_t>, std::array<uint8_t, BLOCK_SIZE>> keyIv = {
            keyRequest->key.first,
            keyRequest->key.second
        };

        // Initialize the AES CBC encryptor with the key and IV
        AESCBC aesEncryptor(keyIv);

        // Encrypt the serialized packet
        encryptedData = aesEncryptor.encrypt(serializedPacket);
        pakageIdUnit8.insert(pakageIdUnit8.end(),encryptedData.begin(),encryptedData.end());
        encryptedData = pakageIdUnit8;
        pakageIdUnit8 = {};
    }
   
    // Return the final encrypted data and the first node
    return { encryptedData, nodes.front() };
}


std::vector<uint8_t> OnionManager::EncryptWithPublicKey(const Node& node, const std::vector<uint8_t>& data) {
    // Step 1: Convert the data into a string (if necessary for encryption)
    std::string dataStr(data.begin(), data.end());

    // Step 2: Use the node's public key to encrypt the data
    std::vector<uint64_t> encryptedData = AsymmetricEncryption::EncryptWithExternalPublicKey(dataStr, node.public_Key);

    // Step 3: Convert encrypted data to uint8_t vector (assuming you need this format)
    std::vector<uint8_t> encryptedBytes;
    for (const uint64_t& block : encryptedData) {
        // Convert each uint64_t block to a byte array and append to the result
        for (size_t i = 0; i < sizeof(uint64_t); ++i) {
            encryptedBytes.push_back(static_cast<uint8_t>((block >> (i * 8)) & 0xFF));
        }
    }


    // Step 5: Return the encrypted data
    return encryptedBytes;
}

std::vector<uint8_t> OnionManager::EncryptWithPublicKey(const std::pair<uint64_t, uint64_t>& public_Key, const std::vector<uint8_t>& data) {
    // Step 1: Convert the data into a string (if necessary for encryption)
    std::string dataStr(data.begin(), data.end());

    // Step 2: Use the node's public key to encrypt the data
    std::vector<uint64_t> encryptedData = AsymmetricEncryption::EncryptWithExternalPublicKey(dataStr,public_Key);

    // Step 3: Convert encrypted data to uint8_t vector (assuming you need this format)
    std::vector<uint8_t> encryptedBytes;
    for (const uint64_t& block : encryptedData) {
        // Convert each uint64_t block to a byte array and append to the result
        for (size_t i = 0; i < sizeof(uint64_t); ++i) {
            encryptedBytes.push_back(static_cast<uint8_t>((block >> (i * 8)) & 0xFF));
        }
    }


    // Step 5: Return the encrypted data
    return encryptedBytes;
}

const std::pair<uint64_t, uint64_t>& OnionManager::GetPublicKey() const
{
    return m_publicKey;
}

