#include "vault_invalid_json.hpp"

VaultInvalidJSON::VaultInvalidJSON(const std::string &existing_vault) : message("Invalid JSON in vault file: " + existing_vault) {}

const char* VaultInvalidJSON::what() const noexcept {
    return message.c_str();
}
