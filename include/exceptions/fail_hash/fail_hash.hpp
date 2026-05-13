#pragma once
#include <string>
#include <exception>

class FailHash : public std::exception {
protected:
    std::string message;
public:
    FailHash();
    virtual const char* what() const noexcept override;
};