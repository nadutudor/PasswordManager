#pragma once
#include <string>
#include <exception>

class NotTypeDirectory : public std::exception {
    std::string message;
public:
    explicit NotTypeDirectory(const std::string& parent_directory);
    virtual const char* what() const noexcept override;
};