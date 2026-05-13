#pragma once
#include <string>
#include <exception>

class VaultNotFoundException : public std::exception {
    std::string message;
public:
    VaultNotFoundException();
    virtual const char* what() const noexcept override;
};