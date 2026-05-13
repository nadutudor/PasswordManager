#pragma once
#include <string>
#include <iostream>
#include "../category/category.hpp"
#include "../folder/folder.hpp"
#include "../logincredentials/logincredentials.hpp"

class Login
{
    std::string item_name;
    Category category;
    Folder folder;
    LoginCredentials loginInfo;
    std::string link;
    std::string notes;

public:
    Login();
    Login(const std::string &item_name, const Category &category, const Folder &folder,
          const LoginCredentials &loginInfo, const std::string &link,
          const std::string &notes);
    friend std::ostream &operator<<(std::ostream &os, const Login &old_login);
    const std::string &getItemName() const;
    const Category &getCategory() const;
    const Folder &getFolder() const;
    const LoginCredentials &getLoginInfo() const;
    const std::string &getLink() const;
    const std::string &getNotes() const;
};