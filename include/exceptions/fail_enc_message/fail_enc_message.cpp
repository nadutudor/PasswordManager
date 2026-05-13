#include "fail_enc_message.hpp"

FailEncMessage::FailEncMessage() : message("Failed to encrypt the message \n") {}

const char* FailEncMessage::what() const noexcept {
    return message.c_str();
}
