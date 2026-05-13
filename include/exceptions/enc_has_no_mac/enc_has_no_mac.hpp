#pragma once
#include <string>
#include <exception>

class EncHasNoMAC : public std::exception {
    std::string message;
public:
    EncHasNoMAC();
    virtual const char* what() const noexcept override;
};