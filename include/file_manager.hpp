// TODO: Remove outputs, to use only return values

#pragma once
#include <iostream>
#include <fstream>
#include <filesystem>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;


class Files
{
    std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>> paths;

public:
    explicit Files(const std::filesystem::path &parent_directory)
    {
        if (!std::filesystem::exists(parent_directory))
        {
            
            std::cerr << parent_directory << " does not exist.";
            return;
        }
        if (!std::filesystem::is_directory(parent_directory))
        {
            std::cerr << parent_directory << " is not a directory.";
            return;
        }
        for (auto const &file : std::filesystem::directory_iterator{parent_directory})
        {
            std::ifstream fin(file.path());
            json vault;
            fin >> vault;
            if (!vault.contains("salt") || !vault.contains("dummy"))
            {
                std::cerr << "Invalid vault file.";
                return;
            }
            std::string salt_b64 = vault["salt"];
            std::vector<unsigned char> dummy_bin_container = Base64ToBin(vault["dummy"]);
            std::vector<unsigned char> dummy_bin;
            dummy_bin.insert(dummy_bin.begin(), dummy_bin_container.begin() + 24, dummy_bin_container.end());
            std::vector<unsigned char> dummy_nonce_bin;
            dummy_nonce_bin.insert(dummy_nonce_bin.begin(), dummy_bin_container.begin(), dummy_bin_container.begin() + 24);
            paths[file.path()][0] = Base64ToBin(salt_b64);
            paths[file.path()][1] = dummy_bin;
            paths[file.path()][2] = dummy_nonce_bin;
        }
    }
    friend std::ostream &operator<<(std::ostream &os, const Files &old_files)
    {
        for (auto const &key : old_files.paths)
        {
            os << key.first.string() << '\n';
        }
        return os;
    }
    const std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>> &getPaths() const
    {
        return paths;
    }
};