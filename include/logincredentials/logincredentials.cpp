#include "logincredentials.hpp"


LoginCredentials::LoginCredentials() = default;

LoginCredentials::LoginCredentials(const std::string &username, const Message &password) : username{username}, password{password} {}

std::ostream &operator<<(std::ostream &os, const LoginCredentials &old_loginCred)
{
    os << old_loginCred.username << " " << old_loginCred.password << " \n";
    return os;
}

const Message& LoginCredentials::getPassword() const
{
    return password;
}

const std::string& LoginCredentials::getUsername() const
{
    return username;
}
