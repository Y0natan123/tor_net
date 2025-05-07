#ifndef AESCBC_H
#define AESCBC_H

#include <iostream> 
#include <iomanip> 
#include <vector>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <random>
#include <algorithm>

const int BLOCK_SIZE = 16;  // AES block size in bytes
const int KEY_SIZE = 16;    // AES key size in bytes (128-bit)
const int ROUNDS = 10;      // Number of rounds for AES (for 128-bit key)

class AESCBC
{
public:
    // Constructor that initializes the key and performs key expansion
    AESCBC(const std::pair< std::vector<uint8_t>,std::array<uint8_t, BLOCK_SIZE>>& keyIv);
    static std::pair< std::vector<uint8_t>,std::array<uint8_t, BLOCK_SIZE>> generateRandomKey();
    // Encrypts the input data using AES CBC mode
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);

    // Decrypts the input data using AES CBC mode
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);

private:
    // Padding and unpadding methods
    void pad(std::vector<uint8_t>& data);
    void unpad(std::vector<uint8_t>& data);

    // Generate a random initialization vector (IV)
    static std::array<uint8_t, BLOCK_SIZE> generateRandomIv();

    // XOR the current block with a given block (used for CBC mode)
    void xorBlock(std::array<uint8_t, BLOCK_SIZE>& block, const std::array<uint8_t, BLOCK_SIZE>& xorBlock);

    // AES round procedure (encryption or decryption)
    void aesRound(std::array<uint8_t, BLOCK_SIZE>& block, bool encrypt, bool isFinalRound);

    // Substitution step in AES (SubBytes)
    void subBytes(std::array<uint8_t, BLOCK_SIZE>& state, bool encrypt);

    // Row shift step in AES (ShiftRows)
    void shiftRows(std::array<uint8_t, BLOCK_SIZE>& state, bool encrypt);

    // Mix columns step in AES (MixColumns)
    void mixColumns(std::array<uint8_t, BLOCK_SIZE>& state, bool encrypt);

    uint8_t GF_Multiply(uint8_t a, uint8_t b);

    // AddRoundKey step in AES
    void addRoundKey(std::array<uint8_t, BLOCK_SIZE>& state, const uint8_t* roundKey);

    // Key expansion function to generate round keys
    void keyExpansion();


    std::array<uint8_t, KEY_SIZE> key_;  // AES key
    std::array<uint8_t, BLOCK_SIZE> iv_; // Initialization vector
    std::array<uint8_t, (ROUNDS + 1)* BLOCK_SIZE> roundKeys_;  // Round keys (expanded)
    const uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };  // AES round constants
};

#endif // AESCBC_H
