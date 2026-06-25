#pragma once
#include <string>
#include <iostream>
#include "../unit/unit.hpp"

struct CategoryTag{};

class Category : public Unit<CategoryTag>{
public:
    Category(const std::string &s);
    Category();
};