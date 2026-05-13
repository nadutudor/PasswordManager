#pragma once
#include <string>
#include <exception>

class FailEncMessage : public std::exception {
    std::string message;
public:
    FailEncMessage();
    virtual const char* what() const noexcept override;
};