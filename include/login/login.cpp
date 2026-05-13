#include "login.hpp"

Login::Login() = default;

Login::Login(const std::string &item_name, const Category &category, const Folder &folder,
        const LoginCredentials &loginInfo, const std::string &link,
        const std::string &notes) : item_name{item_name}, category{category}, folder{folder}, loginInfo{loginInfo}, link{link}, notes{notes} {}

std::ostream &operator<<(std::ostream &os, const Login &old_login)
{
    os << old_login.item_name << " " << old_login.category << " " << old_login.loginInfo << " " << old_login.link << " \n"
        << old_login.notes << " \n";
    return os;
}

const std::string& Login::getItemName() const
{
    return item_name;
}
const Category& Login::getCategory() const
{
    return category;
}
const Folder& Login::getFolder() const
{
    return folder;
}
const LoginCredentials& Login::getLoginInfo() const
{
    return loginInfo;
}
const std::string& Login::getLink() const
{
    return link;
}
const std::string& Login::getNotes() const
{
    return notes;
}
