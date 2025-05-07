#ifndef SINK_H
#define SINK_H


#include <array>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <map>
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include "SqliteDatabase.h"

class Sink {
public:
    // Constructor and Destructor
    Sink();
    ~Sink();
    bool insertPublicKey(std::pair<uint64_t, uint64_t> key,std::string IP,int port);
    bool deletePublicKey(std::string IP, int port);
    GetKeysResponse getKeys(std::string IP = "0.0.0.0", int port = 0);

    void deleteNode(std::vector<Node>& nodes, const Node& nodeToDelete);


private:

    SqliteDatabase* DataB;
    int m_onionId;
    std::map<uint32_t, std::string> m_nodeManager; // Node manager for route selection and management

    static constexpr size_t BLOCK_SIZE = 64; // 512 bits / 8
    static constexpr size_t HASH_SIZE = 32;  // 256 bits / 8

    // SHA-256 constants
   /* static const std::array<uint32_t, 64> K;
    std::string SHA256HashPassword(const std::string& password);
    static void transform(uint32_t state[8], const uint8_t block[BLOCK_SIZE]);
    static std::string toHexString(const uint8_t* data, size_t length);*/

};

#endif // SINK_H


//const std::array<uint32_t, 64> Sink::K = {
//    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
//    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
//    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
//    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
//    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
//    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
//    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
//    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
//    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
//    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
//    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
//    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
//    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
//    0x391c0cb3, 0x4ed8aa11, 0x5b9cca4f, 0x682e6ff3,
//    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
//    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
//};