#ifndef ERRORHANDLING_H
#define ERRORHANDLING_H

#include <string>
#include <iostream>
#include <cstring>
class ErrorHandling {
public:
    // ������� ������ ������� ������
    void HandleError(const std::string& errorMessage);

    // ������� ������ ������� �� �����
    void HandleEncryptionError(const std::string& errorMessage);

    // ������� ������ ������� �� ������ ������
    void HandlePacketError(const std::string& errorMessage);

    // ������� ������ ������� �� ������
    void HandleCommunicationError(const std::string& errorMessage);

    // ������� ������ ����� ����� �����
    void PrintError(const std::string& errorMessage);
};

#endif // ERRORHANDLING_H
