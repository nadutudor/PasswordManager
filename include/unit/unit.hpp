#pragma once
#include <string>
#include <iostream>

template <typename Tag>
class Unit
{
    std::string name;

public:
    Unit() = default;
    explicit Unit(const std::string &name) : name{name} {}
    explicit Unit(const Unit &old_unit) : name{old_unit.name} {}

    void operator=(const Unit &old_unit)
    {
        name = old_unit.name;
    }

    ~Unit() = default;

    friend std::ostream &operator<<(std::ostream &os, const Unit<Tag> &old_unit){
        return os << old_unit.name << " \n";
    }

    bool operator<(const Unit &old_unit)
    {
        return name < old_unit.name;
    }
};