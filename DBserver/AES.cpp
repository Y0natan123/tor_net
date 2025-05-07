#include "AES.h"

// AES S-box for substitution
const uint8_t sbox[256] = 
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Inverse S-box for SubBytes in decryption
const uint8_t inv_sbox[256] =
{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};


std::pair< std::vector<uint8_t>,std::array<uint8_t, BLOCK_SIZE>> AESCBC::generateRandomKey()
{
    std::pair< std::vector<uint8_t>,std::array<uint8_t, BLOCK_SIZE>> ret;
    std::array<uint8_t, BLOCK_SIZE> iv_ = generateRandomIv();
    std::vector<uint8_t> key(KEY_SIZE);
    
    // Initialize random number generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);

    // Fill the key with random bytes
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        key[i] = dis(gen);
    }
    ret.first = key;
    ret.second = iv_;
    return ret;
}

AESCBC::AESCBC(const std::pair< std::vector<uint8_t>,std::array<uint8_t, BLOCK_SIZE>>& keyIv) 
{
    if (keyIv.first.size() != KEY_SIZE) 
    {
        throw std::invalid_argument("Invalid key size");
    }
    std::copy(keyIv.first.begin(), keyIv.first.end(), key_.begin());
    iv_ = keyIv.second;
    keyExpansion();  // Perform key expansion to generate round keys
}

void AESCBC::keyExpansion() 
{
    uint8_t temp[4];  // Temporary word used for key expansion
    size_t keySize = KEY_SIZE; // 16 bytes for AES-128

    // Copy the key into the first part of the round key array
    for (size_t i = 0; i < keySize; i++) 
    {
        roundKeys_[i] = key_[i];
    }

    // Generate the remaining round keys
    for (size_t i = keySize; i < 176; i += 4) // 176 bytes for 128-bit AES
    { 
        temp[0] = roundKeys_[i - 4];
        temp[1] = roundKeys_[i - 3];
        temp[2] = roundKeys_[i - 2];
        temp[3] = roundKeys_[i - 1];

        if (i % 16 == 0) // Every 16 bytes, apply the key schedule core
        {  
            // Rotate the word (left shift)
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // Apply S-box
            for (int j = 0; j < 4; j++) 
            {
                temp[j] = sbox[temp[j]];
            }

            // Apply round constant
            temp[0] ^= rcon[i / 16];  // round constant
        }

        // XOR the temp with the word 16 bytes before it
        roundKeys_[i] = roundKeys_[i - 16] ^ temp[0];
        roundKeys_[i + 1] = roundKeys_[i - 15] ^ temp[1];
        roundKeys_[i + 2] = roundKeys_[i - 14] ^ temp[2];
        roundKeys_[i + 3] = roundKeys_[i - 13] ^ temp[3];
    }
}

void AESCBC::subBytes(std::array<uint8_t, BLOCK_SIZE>& state, bool encrypt) 
{
    for (int i = 0; i < BLOCK_SIZE; i++) 
    {
        state[i] = encrypt ? sbox[state[i]] : inv_sbox[state[i]];
    }
}

void AESCBC::shiftRows(std::array<uint8_t, BLOCK_SIZE>& state, bool encrypt) 
{
    std::array<uint8_t, BLOCK_SIZE> temp = state;

    if (encrypt) 
    {
        // Encryption-specific row shifts
        //state[0] stay the same
        state[1] = temp[5];
        state[2] = temp[10];
        state[3] = temp[15];
        //4
        state[5] = temp[9]; 
        state[6] = temp[14];
        state[7] = temp[3];
        //8
        state[9] = temp[13]; 
        state[10] = temp[2];
        state[11] = temp[7];
        //12
        state[13] = temp[1];
        state[14] = temp[6];
        state[15] = temp[11];
    }
    else 
    {
        // Decryption-specific row shifts (reverse shifts)
        //0
        state[1] = temp[13]; 
        state[2] = temp[10];
        state[3] = temp[7];
        //4
        state[5] = temp[1]; 
        state[6] = temp[14];
        state[7] = temp[11];
        //8
        state[9] = temp[5]; 
        state[10] = temp[2];
        state[11] = temp[15];
        //12
        state[13] = temp[9];
        state[14] = temp[6];
        state[15] = temp[3];
    }
}


uint8_t AESCBC::GF_Multiply(uint8_t a, uint8_t b) 
{
    uint8_t result = 0;
    while (b) 
    {
        if (b & 1) 
        {
            result ^= a;
        }
        a = (a << 1) ^ (a & 0x80 ? 0x1b : 0);
        b >>= 1;
    }
    return result;
}

void AESCBC::mixColumns(std::array<uint8_t, BLOCK_SIZE>&state, bool encrypt) 
{
    for (int i = 0; i < 4; ++i) 
    {
        std::array<uint8_t, 4> a;
        std::array<uint8_t, 4> b;

        // Copy the column into 'a'
        for (int j = 0; j < 4; ++j) 
        {
            a[j] = state[i + 4 * j];
        }

        // Perform MixColumns or InverseMixColumns based on the 'encrypt' flag
        if (encrypt) 
        {
            // Regular MixColumns using 0x02 (Multiply by 2) and 0x03 (Multiply by 3)
            b[0] = GF_Multiply(a[0], 0x02) ^ GF_Multiply(a[1], 0x03) ^ a[2] ^ a[3];
            b[1] = GF_Multiply(a[1], 0x02) ^ GF_Multiply(a[2], 0x03) ^ a[3] ^ a[0];
            b[2] = GF_Multiply(a[2], 0x02) ^ GF_Multiply(a[3], 0x03) ^ a[0] ^ a[1];
            b[3] = GF_Multiply(a[3], 0x02) ^ GF_Multiply(a[0], 0x03) ^ a[1] ^ a[2];
        }
        else 
        {
            // Inverse MixColumns using inverse constants 0x0E, 0x0B, 0x0D, 0x09
            b[0] = GF_Multiply(a[0], 0x0E) ^ GF_Multiply(a[1], 0x0B) ^ GF_Multiply(a[2], 0x0D) ^ GF_Multiply(a[3], 0x09);
            b[1] = GF_Multiply(a[0], 0x09) ^ GF_Multiply(a[1], 0x0E) ^ GF_Multiply(a[2], 0x0B) ^ GF_Multiply(a[3], 0x0D);
            b[2] = GF_Multiply(a[0], 0x0D) ^ GF_Multiply(a[1], 0x09) ^ GF_Multiply(a[2], 0x0E) ^ GF_Multiply(a[3], 0x0B);
            b[3] = GF_Multiply(a[0], 0x0B) ^ GF_Multiply(a[1], 0x0D) ^ GF_Multiply(a[2], 0x09) ^ GF_Multiply(a[3], 0x0E);
        }

        // Update the state with the mixed values
        for (int j = 0; j < 4; ++j) 
        {
            state[i + 4 * j] = b[j];
        }
    }
}

void AESCBC::addRoundKey(std::array<uint8_t, BLOCK_SIZE>& state, const uint8_t* roundKey) 
{
    for (int i = 0; i < BLOCK_SIZE; i++) 
    {
        state[i] ^= roundKey[i];
    }
}

std::array<uint8_t, BLOCK_SIZE> AESCBC::generateRandomIv() 
{
    std::array<uint8_t, BLOCK_SIZE> iv;
    std::random_device rd;
    std::uniform_int_distribution<unsigned int> dist(0, 255);

    for (int i = 0; i < BLOCK_SIZE; i++) 
    {
        iv[i] = dist(rd);
    }
    return iv;
}

void AESCBC::pad(std::vector<uint8_t>& data) 
{
    int paddingLength = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
    // If the data is already aligned with BLOCK_SIZE, add a full block of padding
    if (paddingLength == 0) 
    {
        paddingLength = BLOCK_SIZE;
    }

    // Add padding bytes (paddingLength value will be repeated)
    data.resize(data.size() + paddingLength, paddingLength);
}

void AESCBC::unpad(std::vector<uint8_t>& data) 
{
    if (data.empty()) return;  // Prevent out-of-bounds error

    uint8_t paddingLength = data.back();  // Get the padding length from the last byte
    
    // Validate padding
    if (paddingLength > 0 && paddingLength <= BLOCK_SIZE) 
    {
        data.resize(data.size() - paddingLength);  // Remove the padding bytes
    }
}

void AESCBC::xorBlock(std::array<uint8_t, BLOCK_SIZE>& block, const std::array<uint8_t, BLOCK_SIZE>& xorBlock) 
{
    for (int i = 0; i < BLOCK_SIZE; i++) 
    {
        block[i] ^= xorBlock[i];  // XOR operation on each byte
    }
}

void AESCBC::aesRound(std::array<uint8_t, BLOCK_SIZE>& block, bool encrypt , bool isFinalRound)
{
    if (encrypt)
    {
        subBytes(block, encrypt);
        shiftRows(block, encrypt);
        if (!isFinalRound) mixColumns(block, encrypt); // Skip MixColumns in final round 
        addRoundKey(block, roundKeys_.data());
    }
    else
    {
        addRoundKey(block, roundKeys_.data());
        if (!isFinalRound) mixColumns(block, encrypt); // Skip invMixColumns in final round 
        shiftRows(block, encrypt);
        subBytes(block, encrypt);
    }

}

std::vector<uint8_t> AESCBC::encrypt(const std::vector<uint8_t>& plaintext) 
{
    // Initialize block and the previous ciphertext (or IV for the first block)
    std::array<uint8_t, BLOCK_SIZE> block;
    std::array<uint8_t, BLOCK_SIZE> previousCiphertext = iv_;

    // Copy plaintext to preserve original
    std::vector<uint8_t> data = plaintext;

    // Apply PKCS#7 padding to the data to make it a multiple of BLOCK_SIZE
    pad(data);

    // Initialize the ciphertext vector and reserve space for performance optimization
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(data.size());

    // Process data in BLOCK_SIZE chunks
    for (size_t i = 0; i < data.size(); i += BLOCK_SIZE) 
    {
        // Copy the current block from data
        std::copy(data.begin() + i, data.begin() + i + BLOCK_SIZE, block.begin());

        // XOR the current block with the previous ciphertext (or IV for the first block)
        xorBlock(block, previousCiphertext);

        // Perform AES rounds
        for (int round = 0; round < ROUNDS; round++)
        {
            aesRound(block, true , round == ROUNDS - 1);
        }

        // Append the encrypted block to ciphertext
        ciphertext.insert(ciphertext.begin()+i, block.begin(), block.end());

        // Update previousCiphertext for the next block
        previousCiphertext = block;
    }

    return ciphertext;  // Return the final encrypted data
}


std::vector<uint8_t> AESCBC::decrypt(const std::vector<uint8_t>& ciphertext) 
{
    if (ciphertext.size() % BLOCK_SIZE != 0)
        throw std::runtime_error("Ciphertext size is not a multiple of BLOCK_SIZE");
    
    std::array<uint8_t, BLOCK_SIZE> block;
    std::array<uint8_t, BLOCK_SIZE> previousCiphertext = iv_;

    std::vector<uint8_t> data = ciphertext;

    // Initialize plaintext vector
    std::vector<uint8_t> plaintext;
    plaintext.reserve(data.size());

    // Process each block of the ciphertext
    for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE)
    {
        std::copy(ciphertext.begin() + i, ciphertext.begin() + i + BLOCK_SIZE, block.begin());

        // Store current ciphertext block before modifying it
        std::array<uint8_t, BLOCK_SIZE> currentCiphertext = block;

        // Perform AES rounds (in reverse order for decryption)
        for (int round = ROUNDS - 1; round >= 0; round--)
        {
            aesRound(block, false , round == ROUNDS - 1);
        }

        // XOR the decrypted block with the previous ciphertext (or IV for the first block)
        xorBlock(block, previousCiphertext);

        // Append decrypted block to plaintext
        plaintext.insert(plaintext.begin()+ i , block.begin(), block.end());

        // Update previousCiphertext for next block
        previousCiphertext = currentCiphertext;
    }
    
    unpad(plaintext);  // Remove padding after decryption

    return plaintext;
}
