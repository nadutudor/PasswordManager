#include "sodium_init_failed.hpp"

SodiumInitFailed::SodiumInitFailed() : message("Failed to initialize libsodium \n") {}

const char* SodiumInitFailed::what() const noexcept {
    return message.c_str();
}
