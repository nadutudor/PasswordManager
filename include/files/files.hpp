// TODO: Remove outputs, to use only return values

#pragma once
#include <iostream>
#include <fstream>
#include <filesystem>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>
#include "utils.hpp"
#include "../exceptions/directory_not_exist/directory_not_exist.hpp"
#include "../exceptions/not_type_directory/not_type_directory.hpp"
#include "../exceptions/failed_open_vault/failed_open_vault.hpp"
#include "../exceptions/vault_invalid_json/vault_invalid_json.hpp"
#include "../vaultindex/vaultindex.hpp"

using json = nlohmann::json;
using VaultMetadata = std::array<std::vector<unsigned char>, 3>;

class Files
{
    VaultIndex<std::filesystem::path, VaultMetadata> paths;

public:
    explicit Files(const std::filesystem::path &parent_directory);
    friend std::ostream &operator<<(std::ostream &os, const Files &old_files);
    const VaultIndex<std::filesystem::path, VaultMetadata> &getPaths() const;
};