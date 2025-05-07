#include "MovieMessageManager.h"
#include <stdexcept>
#include <cstring>

std::vector<uint8_t> MovieMessageManager::serialize(const Message& message) {
    std::vector<uint8_t> data;
    data.push_back(static_cast<uint8_t>(message.type)); // Message type
    uint16_t length = message.length;
    data.push_back(static_cast<uint8_t>(length >> 8)); // High byte of length
    data.push_back(static_cast<uint8_t>(length & 0xFF)); // Low byte of length
    data.insert(data.end(), message.information.begin(), message.information.end()); // Information
    return data;
}

MovieMessageManager::Message MovieMessageManager::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 3) {
        throw std::invalid_argument("Data too short to deserialize");
    }

    Message message;
    message.type = static_cast<MessageType>(data[0]); // Message type
    message.length = (data[1] << 8) | data[2]; // Combine high and low bytes of length

    if (data.size() - 3 != message.length) {
        throw std::invalid_argument("Data length mismatch");
    }

    message.information = std::string(data.begin() + 3, data.end()); // Information
    return message;
}

MovieMessageManager::Message MovieMessageManager::createNoSuchMovieMessage() {
    return { MessageType::NO_SUCH_MOVIE, 0, "" };
}

MovieMessageManager::Message MovieMessageManager::createMovieFoundMessage(const std::string& movieInfo) {
    return { MessageType::MOVIE_FOUND, static_cast<uint16_t>(movieInfo.size()), movieInfo };
}
