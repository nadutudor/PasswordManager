#include "enc_has_no_mac.hpp"

EncHasNoMAC::EncHasNoMAC() : message("Encryption doesn't have MAC tag \n") {}

const char* EncHasNoMAC::what() const noexcept {
    return message.c_str();
}
