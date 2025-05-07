#ifndef ASYMMETRIC_ENCRYPTION_H
#define ASYMMETRIC_ENCRYPTION_H

#include <vector>
#include <cstdint>
#include <utility> // ���� std::pair
#include <string>

class AsymmetricEncryption {
public:
    // Generate a keypair (returns public and private keys)
    static std::pair<std::pair<uint64_t, uint64_t>, std::pair<uint64_t, uint64_t>> GenerateKeypair();

    // Encrypt a message using a public key
    static std::vector<uint64_t> Encrypt(const std::string& message, const std::pair<uint64_t, uint64_t>& publicKey);

    // Decrypt a message using a private key
    static std::string Decrypt(const std::vector<uint64_t>& encryptedData, const std::pair<uint64_t, uint64_t>& privateKey);

    // Encrypt with an external public key
    static std::vector<uint64_t> EncryptWithExternalPublicKey(const std::string& message, const std::pair<uint64_t, uint64_t>& externalPublicKey);

    // Convert raw bytes to a public key
    static std::pair<uint64_t, uint64_t> ConvertToPublicKeyFromBytes(const std::vector<uint8_t>& publicKeyData);

private:
    // Utility methods
    static uint64_t GeneratePrime();
    static uint64_t ModularExponentiation(uint64_t base, uint64_t exp, uint64_t mod);
    static uint64_t ComputeGCD(uint64_t a, uint64_t b);
};

#endif // ASYMMETRIC_ENCRYPTION_H
