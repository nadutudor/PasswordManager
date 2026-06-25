#pragma once
#include <string>
#include <iostream>
#include "../unit/unit.hpp"

struct FolderTag{};

class Folder : public Unit<FolderTag>{
public:
    Folder(const std::string &s);
    Folder();
};