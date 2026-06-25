#pragma once
#include <vector>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include "../login/login.hpp"
#include "../masterkey/masterkey.hpp"
#include "../category/category.hpp"
#include "../utils.hpp"
#include "../folder/folder.hpp"
#include "../logincredentials/logincredentials.hpp"
#include "../message/message.hpp"
#include "../exceptions/failed_open_vault/failed_open_vault.hpp"
#include "../exceptions/failed_open_vault_edit/failed_open_vault_edit.hpp"
#include "../exceptions/vault_invalid_json/vault_invalid_json.hpp"

using json = nlohmann::json;

class Vault
{
    std::vector<Login> items;
    std::filesystem::path path_to_vault;
    MasterKey masterkey;
    static int nextId;
    int vaultId;
public:
    // Create Vault 
    Vault();
    // For an already existing vault
    Vault(const std::filesystem::path &existing_vault, const MasterKey &masterkey);
    const std::vector<Login> &getItems() const;
    const MasterKey &getMasterkey() const;
    void print_options_vault();
    void edit_options_vault();
};