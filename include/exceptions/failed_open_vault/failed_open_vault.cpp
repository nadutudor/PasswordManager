#include "failed_open_vault.hpp"

FailedOpenVault::FailedOpenVault() = default;
FailedOpenVault::FailedOpenVault(const std::string &existing_vault) : message("Failed to open vault file: " + existing_vault) {}

const char* FailedOpenVault::what() const noexcept {
    return message.c_str();
}
