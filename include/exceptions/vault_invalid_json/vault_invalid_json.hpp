#pragma once
#include <string>
#include <exception>

class VaultInvalidJSON : public std::exception {
    std::string message;
public:
    explicit VaultInvalidJSON(const std::string &existing_vault);
    virtual const char* what() const noexcept override;
};