/*
    find_vault() is an extension to VaultInteractionState object. Used to check all the vaults and return the path of the ones that match the master key inserted by the user.
    known_vault() checks if the vault with the name inserted by the user exists and then using the function validate_master_key() checks if the master key is correct.
*/

#include "utils_vault.hpp"

void UtilsVault::find_vault(const std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>> &paths)
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
    try {
        for (const auto &path : paths)
        {
            std::vector<unsigned char> hashed_master_key = Utils::Enc(plain_master_key, path.second[0]);
            if (Utils::validate_master_key(hashed_master_key, path.second[1], path.second[2]))
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
        throw VaultNotFoundException();
    }
    catch(const VaultNotFoundException &e) {
        std::cerr<<e.what();
    }
    
    sodium_memzero(plain_master_key.data(), plain_master_key.size());
    plain_master_key.clear();
}

std::tuple<std::string, MasterKey> UtilsVault::known_vault(const std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>> &paths, const std::string &path_of_vaults)
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
    try {
        if (paths.find(full_path) == paths.end())
            throw VaultNotFoundException();
    }
    catch(const VaultNotFoundException &e) {
        std::cerr<<e.what();

        sodium_memzero(plain_master_key.data(), plain_master_key.size());
        plain_master_key.clear();
        return{"", MasterKey()};
    }

    std::vector<unsigned char> hashed_master_key = Utils::Enc(plain_master_key, paths.at(full_path)[0]);

    // zero the data in RAM, basically "erasing" the data
    sodium_memzero(plain_master_key.data(), plain_master_key.size());
    plain_master_key.clear();
    try {
        if(!Utils::validate_master_key(hashed_master_key, paths.at(full_path)[1], paths.at(full_path)[2]))
            throw MasterKeyMismatchException();
    }
    catch(const MasterKeyMismatchException &e){
        std::cerr<<e.what();

        return{"", MasterKey()};
    }

    return {full_path, MasterKey(hashed_master_key, paths.at(full_path)[0])};
}