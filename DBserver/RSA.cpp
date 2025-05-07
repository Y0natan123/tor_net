#include "RSA.h"
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>

uint64_t AsymmetricEncryption::GeneratePrime() {
    static const std::vector<uint64_t> primes = { 101, 103, 107, 109, 113, 127, 131, 137, 139 };
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, primes.size() - 1);
    return primes[dist(gen)];
}

uint64_t AsymmetricEncryption::ModularExponentiation(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

uint64_t AsymmetricEncryption::ComputeGCD(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

std::pair<std::pair<uint64_t, uint64_t>, std::pair<uint64_t, uint64_t>> AsymmetricEncryption::GenerateKeypair() {
    uint64_t p = GeneratePrime();
    uint64_t q = GeneratePrime();
    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);

    uint64_t e = 3;
    while (ComputeGCD(e, phi) != 1) {
        ++e;
    }

    uint64_t d = 1;
    while ((e * d) % phi != 1) {
        ++d;
    }

    return { {e, n}, {d, n} }; // Public key and private key
}

std::vector<uint64_t> AsymmetricEncryption::Encrypt(const std::string& message, const std::pair<uint64_t, uint64_t>& publicKey) {
    std::vector<uint64_t> encrypted;
    uint64_t e = publicKey.first;
    uint64_t n = publicKey.second;

    for (char c : message) {
        uint64_t encryptedChar = ModularExponentiation(static_cast<uint64_t>(c), e, n);
        encrypted.push_back(encryptedChar);
    }
    return encrypted;
}

std::string AsymmetricEncryption::Decrypt(const std::vector<uint64_t>& encryptedData, const std::pair<uint64_t, uint64_t>& privateKey) {
    std::string decrypted;
    uint64_t d = privateKey.first;
    uint64_t n = privateKey.second;

    for (uint64_t c : encryptedData) {
        uint64_t decryptedChar = ModularExponentiation(c, d, n);
        decrypted += static_cast<char>(decryptedChar);
    }
    return decrypted;
}

std::vector<uint64_t> AsymmetricEncryption::EncryptWithExternalPublicKey(const std::string& message, const std::pair<uint64_t, uint64_t>& externalPublicKey) {
    uint64_t e = externalPublicKey.first;
    uint64_t n = externalPublicKey.second;

    if (n <= 1 || e <= 0) {
        throw std::runtime_error("Invalid external public key.");
    }

    std::vector<uint64_t> encryptedData;
    for (char c : message) {
        uint64_t encryptedChar = ModularExponentiation(static_cast<uint64_t>(c), e, n);
        encryptedData.push_back(encryptedChar);
    }

    return encryptedData;
}

std::pair<uint64_t, uint64_t> AsymmetricEncryption::ConvertToPublicKeyFromBytes(const std::vector<uint8_t>& publicKeyData) {
    if (publicKeyData.size() < 16) {
        throw std::runtime_error("Invalid public key size. Expected at least 16 bytes.");
    }

    uint64_t e = 0, n = 0;

    for (size_t i = 0; i < 8; ++i) {
        e = (e << 8) | publicKeyData[i];
    }

    for (size_t i = 8; i < 16; ++i) {
        n = (n << 8) | publicKeyData[i];
    }

    return { e, n };
}