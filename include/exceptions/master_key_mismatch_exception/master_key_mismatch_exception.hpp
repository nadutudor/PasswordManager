#pragma once
#include <string>
#include <exception>

class MasterKeyMismatchException : public std::exception {
    std::string message;
public:
    MasterKeyMismatchException();
    virtual const char* what() const noexcept override;
};