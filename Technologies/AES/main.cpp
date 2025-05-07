#include "AES.h"
#include <iostream>
#include <vector>
#include <string>

// Function to print a vector
void printVector(const std::vector<uint8_t>& vec) {
    for (auto byte : vec) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
}

// Function to print an array
void printArray(const std::array<uint8_t, BLOCK_SIZE>& arr) {
    for (auto byte : arr) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
}

int main() 
{

    //// Define the key (should be 16 bytes for AES-128)
    std::pair< std::vector<uint8_t>,std::array<uint8_t, BLOCK_SIZE>> key;
    key = AESCBC::generateRandomKey();
    AESCBC aes(key);
    std::cout << "Vector key: ";
    printVector(key.first);
    std::cout << "\nArray key: ";
    printArray(key.second);
    //// Input plaintext as a string
    std::string input = "This is a test string for AES CBC encryption!";

    //// Convert string to vector<uint8_t> (byte array)
    std::vector<uint8_t> plaintext(input.begin(), input.end());

    //
    //// Encrypt the plaintext
    std::vector<uint8_t> ciphertext = aes.encrypt(plaintext);
    AESCBC aes2(key);   
    //// Decrypt the ciphertext back to plaintext
    std::vector<uint8_t> decrypted = aes2.decrypt(ciphertext);
     
    //// Convert decrypted vector back to a string
    std::string decrypted_str(decrypted.begin(), decrypted.end());

    //// Output the results
    std::cout << "Original Plaintext: " << input << std::endl;

    std::cout << "Ciphertext (hex): ";
    for (auto& c : ciphertext) {
        std::cout << std::hex << static_cast<int>(c) << " ";
    }
    std::cout << std::endl;

    std::cout << "Decrypted Plaintext: " << decrypted_str << std::endl;

    return 0;
}
