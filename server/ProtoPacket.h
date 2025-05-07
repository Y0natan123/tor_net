// ProtoPacket.h

#define PROTO_PACKET_H
#include <iostream>
#include <vector>
#include <cstdint>
#include "json.hpp"


struct NextNode {
    uint32_t IPdestination; // ����� ���� �� ������
    uint32_t PORTdestination;
    std::vector<uint8_t> encryptedData;
};


struct OnionHead {
    std::string IPdestination; // ����� ���� �� ������
    uint32_t PORTdestination;
    uint32_t layerCount;  // ���� ������
    uint16_t lengthInfo;
    uint8_t typeInfo;

};

struct OnionBody {
    std::vector<uint8_t> encryptedData;  // ������� ��������
};

class ProtoPacket {
public:

    OnionHead o_head;
    OnionBody o_body;

    // �������� ����������� �������������
    std::vector<uint8_t> serialize() const;
    void deserialize(const std::vector<uint8_t>& data);
};


