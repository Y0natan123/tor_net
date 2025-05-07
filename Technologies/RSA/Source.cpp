#include "RSA.h"

#include <iostream>
#include <vector>

int main() {
    // Generate keypair
    std::pair<std::pair<uint64_t, uint64_t>, std::pair<uint64_t, uint64_t>> publicAndPrivetKeys = AsymmetricEncryption::GenerateKeypair();
    std::pair<uint64_t, uint64_t> publicKey = publicAndPrivetKeys.first;
    std::pair<uint64_t, uint64_t> privateKey = publicAndPrivetKeys.second;
    std::cout << "Public Key: (" << publicKey.first << ", " << publicKey.second << ")\n";
    std::cout << "Private Key: (" << privateKey.first << ", " << privateKey.second << ")\n";

    // Original message
    std::string message = "Hello RSA!";
    std::cout << "Original Message: " << message << "\n";

    // Encrypt the message
    auto encrypted = AsymmetricEncryption::Encrypt(message, publicKey);
    std::cout << "Encrypted: ";
    for (auto c : encrypted) {
        std::cout << c << " ";
    }
    std::cout << "\n";

    // Decrypt the message
    auto decrypted = AsymmetricEncryption::Decrypt(encrypted, privateKey);
    std::cout << "Decrypted: " << decrypted << "\n";

    // Example external public key in raw bytes
    std::vector<uint8_t> externalKeyBytes = { 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 
                                              0x00, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x00, 0xA3 };
    try {
        // Convert external public key
        auto externalPublicKey = AsymmetricEncryption::ConvertToPublicKeyFromBytes(externalKeyBytes);

        // Encrypt with external public key
        auto encryptedWithExternal = AsymmetricEncryption::EncryptWithExternalPublicKey(message, externalPublicKey);
        std::cout << "Encrypted with External Public Key: ";
        for (auto c : encryptedWithExternal) {
            std::cout << c << " ";
        }
        std::cout << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error using external public key: " << e.what() << "\n";
    }

    return 0;
}
