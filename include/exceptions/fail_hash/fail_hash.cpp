#include "fail_hash.hpp"

FailHash::FailHash() : message("Failed to hash \n") {}

const char* FailHash::what() const noexcept {
    return message.c_str();
}
