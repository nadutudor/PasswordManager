// TODO: Remove outputs, to use only return values

#include "files.hpp"

Files::Files(const std::filesystem::path &parent_directory)
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
        if (file.path().extension() != ".json")
        {
            continue;
        }
        std::ifstream fin(file.path());
        if (!fin.is_open())
        {
            std::cerr << "Failed to open vault file: " << file.path() << '\n';
            continue;
        }

        json vault;
        try
        {
            fin >> vault;
        }
        catch (const json::parse_error &err)
        {
            std::cerr << "Invalid JSON in vault file: " << file.path() << " - " << err.what() << '\n';
            continue;
        }

        if (!vault.contains("salt") || !vault.contains("dummy"))
        {
            std::cerr << "Invalid vault file: " << file.path() << '\n';
            continue;
        }
        std::string salt_b64 = vault["salt"];
        std::vector<unsigned char> dummy_bin_container = Utils::Base64ToBin(vault["dummy"]);
        std::vector<unsigned char> dummy_bin;
        dummy_bin.insert(dummy_bin.begin(), dummy_bin_container.begin() + 24, dummy_bin_container.end());
        std::vector<unsigned char> dummy_nonce_bin;
        dummy_nonce_bin.insert(dummy_nonce_bin.begin(), dummy_bin_container.begin(), dummy_bin_container.begin() + 24);
        paths[file.path()][0] = Utils::Base64ToBin(salt_b64);
        paths[file.path()][1] = dummy_bin;
        paths[file.path()][2] = dummy_nonce_bin;
    }
}

std::ostream &operator<<(std::ostream &os, const Files &old_files)
{
    for (auto const &key : old_files.paths)
    {
        os << key.first.string() << '\n';
    }
    return os;
}

const std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>>& Files::getPaths() const
{
    return paths;
}
