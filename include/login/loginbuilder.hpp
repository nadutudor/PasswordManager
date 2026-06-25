#pragma once
#include "login.hpp"
#include "../category/category.hpp"
#include "../folder/folder.hpp"
#include "../logincredentials/logincredentials.hpp"
#include <string>

class LoginBuilder
{
private:
    std::string item_name;
    Category category;
    Folder folder;
    LoginCredentials loginInfo;
    std::string link;
    std::string notes;

public:
    LoginBuilder();
    
    LoginBuilder& setItemName(const std::string& name);
    LoginBuilder& setCategory(const Category& cat);
    LoginBuilder& setFolder(const Folder& fld);
    LoginBuilder& setLoginInfo(const LoginCredentials& info);
    LoginBuilder& setLink(const std::string& url);
    LoginBuilder& setNotes(const std::string& note);
    
    Login build() const;
};
