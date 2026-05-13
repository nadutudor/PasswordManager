#pragma once
#include <string>
#include <iostream>

class Category
{
    std::string name;

public:
    Category();
    explicit Category(const std::string &name);
    explicit Category(const Category &old_category);
    void operator=(const Category &old_category);
    ~Category();
    friend std::ostream &operator<<(std::ostream &os, const Category &old_category);
    bool operator<(const Category &old_category);
};