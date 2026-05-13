#pragma once
#include <string>
#include <exception>

class FailedOpenVault : public std::exception {
protected:
    std::string message;
public:
    FailedOpenVault();
    explicit FailedOpenVault(const std::string &existing_vault);
    virtual const char* what() const noexcept override;
};