#pragma once
#include <string>
#include <iostream>
#include "../message/message.hpp"

class LoginCredentials
{
    std::string username;
    Message password;

public:
    LoginCredentials();
    LoginCredentials(const std::string &username, const Message &password);
    friend std::ostream &operator<<(std::ostream &os, const LoginCredentials &old_loginCred);
    const Message &getPassword() const;
    const std::string &getUsername() const;
};