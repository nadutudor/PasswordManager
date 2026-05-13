#pragma once
#include <string>
#include <exception>

class SodiumInitFailed : public std::exception {
    std::string message;
public:
    SodiumInitFailed();
    virtual const char* what() const noexcept override;
};