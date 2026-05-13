#include "category.hpp"

Category::Category() = default;

Category::Category(const std::string &name) : name{name} {}

Category::Category(const Category &old_category) : name{old_category.name} {}

void Category::operator=(const Category &old_category)
{
    name = old_category.name;
}

Category::~Category() = default;

std::ostream &operator<<(std::ostream &os, const Category &old_category)
{
    return os << old_category.name << " \n";
}

bool Category::operator<(const Category &old_category)
{
    return name < old_category.name;
}
