#pragma once
#include <string>
#include <iostream>

class Folder
{
    std::string name;

public:
    Folder();
    explicit Folder(const std::string &name);
    explicit Folder(const Folder &old_category);
    void operator=(const Folder &old_category);
    ~Folder();
    friend std::ostream &operator<<(std::ostream &os, const Folder &old_category);
    bool operator<(const Folder &old_folder);
};