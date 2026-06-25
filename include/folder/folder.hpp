#pragma once
#include <string>
#include <iostream>
#include "../unit/unit.hpp"

struct FolderTag{};

class Folder : public Unit<FolderTag>{
public:
    explicit Folder(const std::string &s);
    Folder();
};