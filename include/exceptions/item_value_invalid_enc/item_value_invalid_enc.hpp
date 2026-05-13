#pragma once
#include <string>
#include <exception>

class ItemValueInvalidEnc : public std::exception {
    std::string message;
public:
    ItemValueInvalidEnc();
    virtual const char* what() const noexcept override;
};