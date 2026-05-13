#pragma once
#include <string>
#include <exception>

class DirectoryNotExist : public std::exception {
    std::string message;
public:
    explicit DirectoryNotExist(const std::string& parent_directory);
    virtual const char* what() const noexcept override;
};