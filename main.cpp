#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <raylib.h>
#include <RmlUi/Core.h>
#include "include/utils.hpp"
#include "include/file_manager.hpp"
#include "include/vault_components.hpp"

void create_vault()
{
    std::string vaultName;
    std::vector<unsigned char> plain_master_key;
    std::cout << "  Enter vault name:                             \n";
    std::cin >> vaultName;
    std::cout << "  Enter master key:                             \n";
    std::string *plain = new std::string;
    std::cin >> *plain;
    for (const char &t : *plain)
    {
        plain_master_key.push_back(t);
    }
    delete plain;
    sodium_memzero(plain_master_key.data(), plain_master_key.size());
    plain_master_key.clear();
    Vault newVault(vaultName, plain_master_key);
}



void print_options_vault(const Vault &vault)
{
    for (const Login &item : vault.getItems())
    {
        std::cout << "\n"
                  << item.getItemName() << ": \n";
        std::cout << "\t Category: " << item.getCategory() << " \n";
        std::cout << "\t Folder: " << item.getFolder() << " \n";
        std::cout << "\t Category: " << item.getCategory() << " \n";
        std::cout << "\t Link: " << item.getLink() << " \n";
        std::cout << "\t Notes: " << item.getNotes() << " \n";
        std::cout << "\t Login: " << " \n";
        std::cout << "\t\t" << "Username: " << item.getLoginInfo().getUsername() << " \n";
        std::cout << "\t\t" << "Password: " << item.getLoginInfo().getPassword().Decryption(vault.getMasterkey().getHash()) << " \n\n\n\n";
    }
}

// TODO: Rewrite this function
void edit_options_vault(Vault &vault, const std::filesystem::path &path_to_vault)
{
    std::string name, category, folder, link, notes, username, password;

    // Using std::getline to allow spaces in your inputs (like "My Bank Account")
    std::cout << "  Enter item name:                             \n";
    std::getline(std::cin >> std::ws, name);
    std::cout << "  Enter category name:                             \n";
    std::getline(std::cin >> std::ws, category);
    std::cout << "  Enter folder name:                             \n";
    std::getline(std::cin >> std::ws, folder);
    std::cout << "  Enter link:                             \n";
    std::getline(std::cin >> std::ws, link);
    std::cout << "  Enter notes:                             \n";
    std::getline(std::cin >> std::ws, notes);
    std::cout << "  Enter username:                             \n";
    std::getline(std::cin >> std::ws, username);
    std::cout << "  Enter password:                             \n";
    std::getline(std::cin >> std::ws, password);

    // Helper lambda to encrypt a string, pack it with its nonce, and return Base64
    auto encrypt_and_encode = [&](const std::string &input)
    {
        std::vector<unsigned char> plain(input.begin(), input.end());
        Message msg(plain, vault.getMasterkey().getHash());

        std::vector<unsigned char> nonce = msg.getNonce();
        std::vector<unsigned char> cipher = msg.getEncryptedMessage();

        std::vector<unsigned char> container;
        container.reserve(nonce.size() + cipher.size());
        container.insert(container.end(), nonce.begin(), nonce.end());
        container.insert(container.end(), cipher.begin(), cipher.end());

        return BinToBase64(container);
    };

    // Read the existing vault file from disk
    std::ifstream fin(path_to_vault);
    json vault_json;
    if (fin.is_open())
    {
        fin >> vault_json;
        fin.close();
    }
    else
    {
        std::cerr << "Failed to open vault file for editing.\n";
        return;
    }

    // Ensure the items array exists in case this is a brand new vault
    if (!vault_json.contains("items"))
    {
        vault_json["items"] = json::array();
    }

    // Create the new encrypted JSON object
    json new_item;
    new_item["name"] = encrypt_and_encode(name);
    new_item["category"] = encrypt_and_encode(category);
    new_item["folder"] = encrypt_and_encode(folder);
    new_item["link"] = encrypt_and_encode(link);
    new_item["notes"] = encrypt_and_encode(notes);

    json login_info;
    login_info["username"] = encrypt_and_encode(username);
    login_info["password"] = encrypt_and_encode(password);
    new_item["login"] = login_info;

    // Append the new item and overwrite the JSON file
    vault_json["items"].push_back(new_item);

    std::ofstream fout(path_to_vault);
    fout << vault_json.dump(4);
    fout.close();
}

void options_vault(const std::filesystem::path &path_to_vault, const MasterKey &masterkey)
{
    // Create the vault object in memory
    Vault vault(path_to_vault, masterkey);
    int choice;
    bool running = true;
    while (running)
    {
        std::cout << "      Options:                                 \n";
        std::cout << "  [1] Print                             \n";
        std::cout << "  [2] Insert item                              \n";
        std::cout << "  [3] Search                              \n";
        std::cout << "      [4] Return                                 \n";
        std::cin >> choice;
        switch (choice)
        {
        case 1:
            print_options_vault(vault);
            break;
        case 2:
            edit_options_vault(vault, path_to_vault);
            break;
        case 4:
            running = false;
            break;
        }
    }
}

void find_vault(const std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>> &paths)
{
    std::vector<unsigned char> plain_master_key;
    std::cout << "  Enter master key:                             \n";
    std::string *plain = new std::string;
    std::cin >> *plain;
    for (const char &t : *plain)
    {
        plain_master_key.push_back(t);
    }
    delete plain;

    for (const auto &path : paths)
    {
        std::vector<unsigned char> hashed_master_key = Enc(plain_master_key, path.second[0]);
        if (validate_master_key(hashed_master_key, path.second[1], path.second[2]))
        {
            std::cout << "  FILE FOUND:                             \n";
            std::cout << "  Name of the matched file:                             \n";
            std::cout << "  " << path.first.stem().string() << '\n';

            // zero the data in RAM, basically "erasing" the data
            sodium_memzero(plain_master_key.data(), plain_master_key.size());
            plain_master_key.clear();
            return;
        }
    }
    std::cout << "  FILE NOT FOUND                             \n";
}

void known_vault(const std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>> &paths, const std::string &path_of_vaults)
{
    std::string file_name;
    std::cout << "  Enter vault name:                             \n";
    std::cin >> file_name;

    std::vector<unsigned char> plain_master_key;
    std::cout << "  Enter master key:                             \n";
    std::string *plain = new std::string;
    std::cin >> *plain;
    for (const char &t : *plain)
    {
        plain_master_key.push_back(t);
    }
    delete plain;

    // Create a new string for the exact file path to avoid modifying the base path
    std::string full_path = path_of_vaults + file_name + ".json";

    // check if vault file exists with given name
    if (paths.find(full_path) == paths.end())
    {
        std::cerr << "File not found \n";
        return;
    }

    std::vector<unsigned char> hashed_master_key = Enc(plain_master_key, paths.at(full_path)[0]);

    // zero the data in RAM, basically "erasing" the data
    sodium_memzero(plain_master_key.data(), plain_master_key.size());
    plain_master_key.clear();

    if (!validate_master_key(hashed_master_key, paths.at(full_path)[1], paths.at(full_path)[2]))
    {
        std::cerr << "Masterkey doesn't match \n";
        return;
    }

    options_vault(full_path, MasterKey(hashed_master_key, paths.at(full_path)[0]));
}

void enter_vault()
{
    int choice;
    bool running = true;
    std::string path_of_vaults = std::filesystem::current_path().string();
    // Path can be changed at any time
    path_of_vaults.append("/assets/vaults/");
    Files file(path_of_vaults);
    std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>> paths = file.getPaths();

    while (running)
    {
        std::cout << "      Options:                                 \n";
        std::cout << "  [1] Find vault                             \n";
        std::cout << "  [2] Enter vault name                              \n";
        std::cout << "      [3] Return                                 \n";
        std::cin >> choice;
        switch (choice)
        {
        case 1:
            find_vault(paths);
            break;
        case 2:
            known_vault(paths, path_of_vaults);
            break;
        case 3:
            running = false;
            break;
        }
    }
}

void main_prompt()
{
    int choice;
    bool running = true;
    while (running)
    {
        std::cout << "      Options:                                 \n";
        std::cout << "  [1] Create vault                             \n";
        std::cout << "  [2] Enter vault                              \n";
        std::cout << "      [3] Exit                                 \n";
        std::cin >> choice;
        switch (choice)
        {
        case 1:
            create_vault();
            break;
        case 2:
            enter_vault();
            break;
        case 3:
            running = false;
            break;
        }
    }
}

int main()
{
    // Category a("name1");
    // Category b;
    // b = a;
    // std::cout<<b;
    // std::string path_of_vaults = std::filesystem::current_path();
    // // Path can be changed at any time
    // path_of_vaults.append("/assets/vaults/");
    // Files(path_of_vaults.begin());
    main_prompt();

    return 0;
}