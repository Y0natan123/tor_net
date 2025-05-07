#include "ErrorHandling.h"

// ����� ������ �����
void ErrorHandling::HandleError(const std::string& errorMessage) {
    std::cout << "Error: " << errorMessage << std::endl;
    // ������ ����� �������
}

// ����� ������ �����
void ErrorHandling::HandleEncryptionError(const std::string& errorMessage) {
    std::cout << "Encryption Error: " << errorMessage << std::endl;
    // ������ ����� ������� �����, ���� ������ ����� ���� �� ����� �����
}

// ����� ������ ����� �����
void ErrorHandling::HandlePacketError(const std::string& errorMessage) {
    std::cout << "Packet Error: " << errorMessage << std::endl;
    // ������ ����� ������� ������, ��� ������ ����� ����� ��� �� ����� ������
}

// ����� ������ ������
void ErrorHandling::HandleCommunicationError(const std::string& errorMessage) {
    std::cout << "Communication Error: " << errorMessage << std::endl;
    // ������ ����� ������� ������, ���� ����� ������ �����
}

// ����� ����� ����� �����
void ErrorHandling::PrintError(const std::string& errorMessage) {
    std::cout << "Error: " << errorMessage << std::endl;
}
