#include "Sink.h"


#include <sstream>
#include <iomanip>


// Constructor
Sink::Sink() : m_onionId(0) {
    DataB = new SqliteDatabase();
    // Initialization code
}

// Destructor
Sink::~Sink() {
    // Cleanup code
}

bool Sink::insertPublicKey(std::pair<uint64_t, uint64_t> key, std::string IP, int port)
{
    return DataB->insertNode(IP, port, key);
}

bool Sink::deletePublicKey( std::string IP, int port)
{
    return DataB->deleteNode(IP,port);
}

GetKeysResponse Sink::getKeys(std::string IP , int port)
{
    GetKeysResponse Response;
    Response =  DataB->getAllNodesWithKeys();
    for (Node& node : Response.m_public_Keys)
    {
        if (node.IP == IP && node.port == port)
        {
            deleteNode(Response.m_public_Keys, node);
        }
    }
    return Response;
}

void Sink::deleteNode(std::vector<Node>& nodes, const Node& nodeToDelete) {
    nodes.erase(std::remove_if(nodes.begin(), nodes.end(),
        [&](const Node& node) {
            return node == nodeToDelete; // השוואה לפי קריטריון מסוים
        }),
        nodes.end());
}

//
//std::string Sink::SHA256HashPassword(const std::string& password) {
//    // Initialize hash values
//    uint32_t hash[8] = {
//        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
//        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
//    };
//
//    // Pad the input
//    std::vector<uint8_t> paddedPassword;
//    size_t originalByteLen = password.size();
//    size_t originalBitLen = originalByteLen * 8;
//    paddedPassword.assign(password.begin(), password.end());
//
//    paddedPassword.push_back(0x80); // Append a single '1' bit followed by '0's
//    while ((paddedPassword.size() * 8) % 512 != 448) {
//        paddedPassword.push_back(0x00);
//    }
//
//    // Append the original length as a 64-bit big-endian integer
//    for (int i = 7; i >= 0; --i) {
//        paddedPassword.push_back((originalBitLen >> (i * 8)) & 0xff);
//    }
//
//    // Process the message in successive 512-bit chunks
//    for (size_t i = 0; i < paddedPassword.size(); i += BLOCK_SIZE) {
//        transform(hash, paddedPassword.data() + i);
//    }
//
//    return toHexString(reinterpret_cast<uint8_t*>(hash), HASH_SIZE);
//}
//
//void Sink::transform(uint32_t state[8], const uint8_t block[BLOCK_SIZE]) {
//    uint32_t w[64];
//    for (size_t i = 0; i < 16; ++i) {
//        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
//    }
//
//    for (size_t i = 16; i < 64; ++i) {
//        w[i] = w[i - 16] + w[i - 7] + (w[i - 15] >> 3) + (w[i - 2] >> 10); // Σ0 + Σ1
//    }
//
//    uint32_t a = state[0];
//    uint32_t b = state[1];
//    uint32_t c = state[2];
//    uint32_t d = state[3];
//    uint32_t e = state[4];
//    uint32_t f = state[5];
//    uint32_t g = state[6];
//    uint32_t h = state[7];
//
//    for (size_t i = 0; i < 64; ++i) {
//        uint32_t temp1 = h + (e >> 6 | e << (32 - 6)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
//        uint32_t temp2 = (a >> 2 | a << (32 - 2)) + ((a & b) ^ (a & c) ^ (b & c));
//
//        h = g;
//        g = f;
//        f = e;
//        e = d + temp1;
//        d = c;
//        c = b;
//        b = a;
//        a = temp1 + temp2;
//    }
//
//    // Add the compressed chunk to the current hash value
//    state[0] += a;
//    state[1] += b;
//    state[2] += c;
//    state[3] += d;
//    state[4] += e;
//    state[5] += f;
//    state[6] += g;
//    state[7] += h;
//}
//
//std::string Sink::toHexString(const uint8_t* data, size_t length) {
//    std::ostringstream oss;
//    for (size_t i = 0; i < length; ++i) {
//        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
//    }
//    return oss.str();
//}
