#pragma once
#include <vector>
#include <iostream>
#include <string>
#include <filesystem>
#include <unordered_map>
#include <array>
#include <sodium.h>
#include <utils.hpp>
#include <tuple>
#include "masterkey/masterkey.hpp"

namespace UtilsVault{
    void find_vault(const std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>> &paths);

    std::tuple<std::string, MasterKey> known_vault(const std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>> &paths, const std::string &path_of_vaults);
}