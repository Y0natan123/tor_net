#ifndef MOVIEMESSAGEMANAGER_H
#define MOVIEMESSAGEMANAGER_H

#include <string>
#include <vector>
#include <cstdint>

enum class MessageType : uint8_t {
    NO_SUCH_MOVIE = 1,
    MOVIE_FOUND = 2,
    // Add more message types as needed
};

class MovieMessageManager {
public:
    struct Message {
        MessageType type;
        uint16_t length;
        std::string information;
    };

    // Serialize a message into a byte vector
    static std::vector<uint8_t> serialize(const Message& message);

    // Deserialize a byte vector into a message
    static Message deserialize(const std::vector<uint8_t>& data);

    // Utility method to create a "No such movie" message
    static Message createNoSuchMovieMessage();

    // Utility method to create a "Movie found" message
    static Message createMovieFoundMessage(const std::string& movieInfo);
};

#endif // MOVIEMESSAGEMANAGER_H
