#include "folder.hpp"

Folder::Folder() = default;

Folder::Folder(const std::string &name) : name{name} {}

Folder::Folder(const Folder &old_category) : name{old_category.name} {}

void Folder::operator=(const Folder &old_category)
{
    name = old_category.name;
}

Folder::~Folder() = default;

std::ostream &operator<<(std::ostream &os, const Folder &old_category)
{
    return os << old_category.name << " \n";
}

bool Folder::operator<(const Folder &old_folder)
{
    return name < old_folder.name;
}
