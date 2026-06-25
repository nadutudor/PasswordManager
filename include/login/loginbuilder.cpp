#include "loginbuilder.hpp"

LoginBuilder::LoginBuilder()
    : item_name(""), category(""), folder(""), loginInfo(), link(""), notes("")
{
}

LoginBuilder& LoginBuilder::setItemName(const std::string& name)
{
    item_name = name;
    return *this;
}

LoginBuilder& LoginBuilder::setCategory(const Category& cat)
{
    category = cat;
    return *this;
}

LoginBuilder& LoginBuilder::setFolder(const Folder& fld)
{
    folder = fld;
    return *this;
}

LoginBuilder& LoginBuilder::setLoginInfo(const LoginCredentials& info)
{
    loginInfo = info;
    return *this;
}

LoginBuilder& LoginBuilder::setLink(const std::string& url)
{
    link = url;
    return *this;
}

LoginBuilder& LoginBuilder::setNotes(const std::string& note)
{
    notes = note;
    return *this;
}

Login LoginBuilder::build() const
{
    return Login(item_name, category, folder, loginInfo, link, notes);
}
