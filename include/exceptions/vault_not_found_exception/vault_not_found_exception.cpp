#include "vault_not_found_exception.hpp"

VaultNotFoundException::VaultNotFoundException() : message("  FILE NOT FOUND                             \n") {}

const char* VaultNotFoundException::what() const noexcept {
    return message.c_str();
}
