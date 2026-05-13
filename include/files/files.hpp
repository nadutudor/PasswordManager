// TODO: Remove outputs, to use only return values

#pragma once
#include <iostream>
#include <fstream>
#include <filesystem>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>
#include "utils.hpp"

using json = nlohmann::json;


class Files
{
    std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>> paths;

public:
    explicit Files(const std::filesystem::path &parent_directory);
    friend std::ostream &operator<<(std::ostream &os, const Files &old_files);
    const std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>> &getPaths() const;
};