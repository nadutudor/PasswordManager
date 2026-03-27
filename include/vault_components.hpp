// TODO: Remove outputs, to use only return values

#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <sodium.h>
#include <nlohmann/json.hpp>
#include "utils.hpp"

using json = nlohmann::json;

class Message
{
    std::vector<unsigned char> encrypted;
    // used for XChaCha20, always randomly generated; X variant is for a 24-byte nonce
    std::vector<unsigned char> nonce;
    void Encryption(const std::vector<unsigned char> &message, const std::vector<unsigned char> &hashed)
    {
        if (sodium_init() < 0)
        {
            std::cerr << "Failed to initialize libsodium \n";
            return;
        }
        // creating a temporary nonce
        std::vector<unsigned char> tempNonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        randombytes_buf(tempNonce.data(), tempNonce.size());
        // creating a temporary encrypted message
        std::vector<unsigned char> tempEncrypted(message.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long encrypted_len;

        int result = crypto_aead_xchacha20poly1305_ietf_encrypt(tempEncrypted.data(), &encrypted_len, message.data(), message.size(),
                                                                NULL, 0, NULL, tempNonce.data(), hashed.data());
        if (result)
        {
            std::cerr << "Failed to encrypt the message \n";
            return;
        }
        encrypted = tempEncrypted;
        nonce = tempNonce;
    }

public:
    Message() = default;
    Message(const std::vector<unsigned char> &message, const std::vector<unsigned char> &hashed)
    {
        Encryption(message, hashed);
    }
    explicit Message(const std::string &item_value)
    {
        std::vector<unsigned char> binary_item_value = Base64ToBin(item_value);
        // strict 24 bytes of nonce + 16 bytes MAC tag, considering that the message is 0 - worst case. Size at least 40 is a minimum requirement
        if (binary_item_value.size() < 40)
        {
            std::cerr << "Item value is not correctly encrypted \n";
            // to implement std::optional
        }
        else
        {
            nonce.insert(nonce.begin(), binary_item_value.begin(), binary_item_value.begin() + 24);
            encrypted.insert(encrypted.begin(), binary_item_value.begin() + 24, binary_item_value.end());
        }
    }
    friend std::ostream &operator<<(std::ostream &os, const Message &old_password)
    {
        for (const unsigned char &t : old_password.encrypted)
            os << t;
        return os << " \n";
    }
    std::string Decryption(const std::vector<unsigned char> &hashed) const
    {
        if (sodium_init() < 0)
        {
            std::cerr << "Failed to initialize libsodium \n";
            return std::string();
        }
        // check if the encryption even has the MAC tag
        if (encrypted.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        {
            std::cerr << "Encryption doesn't have MAC tag \n";
            return std::string();
        }

        std::vector<unsigned char> decrypted(encrypted.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long decrypted_len;

        int result = crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted.data(), &decrypted_len, nullptr, encrypted.data(), encrypted.size(),
                                                                nullptr, 0, nonce.data(), hashed.data());
        if (result)
        {
            std::cout << "Wrong master key. \n";
            return std::string();
        }
        return std::string(decrypted.begin(), decrypted.end());
    }

    const std::vector<unsigned char> &getEncryptedMessage()
    {
        return encrypted;
    }

    const std::vector<unsigned char> &getNonce()
    {
        return nonce;
    }
};

class MasterKey
{
    // the resulted hashed output from master key and salt
    std::vector<unsigned char> hashed;
    // used for Argon2
    std::vector<unsigned char> salt;

public:
    MasterKey() = default;
    // for newly created masterkey
    explicit MasterKey(std::vector<unsigned char> &plain_master_key)
    {
        if (sodium_init() < 0)
        {
            std::cerr << "Failed to initialize libsodium \n";
            return;
        }

        // creating the salt
        std::vector<unsigned char> localSalt(crypto_pwhash_SALTBYTES);
        randombytes_buf(localSalt.data(), localSalt.size());

        // creating the hash
        std::vector<unsigned char> hashed_output(32);

        int result = crypto_pwhash(hashed_output.data(), hashed_output.size(), reinterpret_cast<const char *>(plain_master_key.data()), plain_master_key.size(), localSalt.data(),
                                   crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_ARGON2ID13);

        if (result)
        {
            std::cerr << "Failed to hash the master key \n";
            std::exit(1);
        }

        // zero the data in RAM, basically "erasing" the data
        sodium_memzero(plain_master_key.data(), plain_master_key.size());
        plain_master_key.clear();
        hashed = hashed_output;
        salt = localSalt;
    }

    // MasterKey initialization constructor
    MasterKey(const std::vector<unsigned char> &hashed, const std::vector<unsigned char> &salt)
    {
        this->hashed = hashed;
        this->salt = salt;
    }

    // for hashing the master key using an already existing salt
    [[maybe_unused]] void HashUsingExistingSalt(std::vector<unsigned char> &plain_master_key, const std::vector<unsigned char> &salt_param)
    {
        if (sodium_init() < 0)
        {
            std::cerr << "Failed to initialize libsodium \n";
            return;
        }

        // creating the hash
        std::vector<unsigned char> hashed_output(32);

        int result = crypto_pwhash(hashed_output.data(), hashed_output.size(), reinterpret_cast<const char *>(plain_master_key.data()), plain_master_key.size(), salt_param.data(),
                                   crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_ARGON2ID13);
        if (result)
        {
            std::cerr << "Failed to hash the master key \n";
            std::exit(1);
        }
        // zero the data in RAM, basically "erasing" the data
        sodium_memzero(plain_master_key.data(), plain_master_key.size());
        plain_master_key.clear();
        hashed = hashed_output;
        salt = salt_param;
    }

    const std::vector<unsigned char> &getHash() const
    {
        return hashed;
    }
    const std::vector<unsigned char> &getSalt() const
    {
        return salt;
    }
};



class Category
{
    std::string name;

public:
    Category() = default;
    explicit Category(const std::string &name) : name{name} {}
    explicit Category(const Category &old_category) : name{old_category.name} {}
    void operator=(const Category &old_category)
    {
        name = old_category.name;
    }
    ~Category() = default;
    friend std::ostream &operator<<(std::ostream &os, const Category &old_category)
    {
        return os << old_category.name << " \n";
    }
    bool operator<(const Category &old_category)
    {
        return name < old_category.name;
    }
};

class LoginCredentials
{
    std::string username;
    Message password;

public:
    LoginCredentials() = default;
    LoginCredentials(const std::string &username, const Message &password) : username{username}, password{password} {}
    friend std::ostream &operator<<(std::ostream &os, const LoginCredentials &old_loginCred)
    {
        os << old_loginCred.username << " " << old_loginCred.password << " \n";
        return os;
    }
    const Message &getPassword() const
    {
        return password;
    }
    const std::string &getUsername() const
    {
        return username;
    }
};

class Folder
{
    std::string name;

public:
    Folder() = default;
    explicit Folder(const std::string &name) : name{name} {}
    explicit Folder(const Folder &old_category) : name{old_category.name} {}
    void operator=(const Folder &old_category)
    {
        name = old_category.name;
    }
    ~Folder() = default;
    friend std::ostream &operator<<(std::ostream &os, const Folder &old_category)
    {
        return os << old_category.name << " \n";
    }
    bool operator<(const Folder &old_folder)
    {
        return name < old_folder.name;
    }
};

class Login
{
    std::string item_name;
    Category category;
    Folder folder;
    LoginCredentials loginInfo;
    std::string link;
    std::string notes;

public:
    Login() = default;
    Login(const std::string &item_name, const Category &category, const Folder &folder,
          const LoginCredentials &loginInfo, const std::string &link,
          const std::string &notes) : item_name{item_name}, category{category}, folder{folder}, loginInfo{loginInfo}, link{link}, notes{notes} {}
    friend std::ostream &operator<<(std::ostream &os, const Login &old_login)
    {
        os << old_login.item_name << " " << old_login.category << " " << old_login.loginInfo << " " << old_login.link << " \n"
           << old_login.notes << " \n";
        return os;
    }
    const std::string &getItemName() const
    {
        return item_name;
    }
    const Category &getCategory() const
    {
        return category;
    }
    const Folder &getFolder() const
    {
        return folder;
    }
    const LoginCredentials &getLoginInfo() const
    {
        return loginInfo;
    }
    const std::string &getLink() const
    {
        return link;
    }
    const std::string &getNotes() const
    {
        return notes;
    }
};

class Vault
{
    std::vector<Login> items;
    MasterKey masterkey;
    // TODO: Add path of the file that contains data for vault to reduce redudancy
public:
    Vault() = default;
    // For an already existing vault
    Vault(const std::filesystem::path &existing_vault, const MasterKey &masterkey) : masterkey{masterkey}
    {
        json vault;
        std::ifstream fin(existing_vault);
        fin >> vault;
        for (const auto &it : vault["items"])
        {
            std::string name = Message(it.at("name").get<std::string>()).Decryption(this->masterkey.getHash());
            Category category(Message(it.at("category").get<std::string>()).Decryption(this->masterkey.getHash()));
            Folder folder(Message(it.at("folder").get<std::string>()).Decryption(this->masterkey.getHash()));
            LoginCredentials loginInfo(Message(it.at("login").at("username").get<std::string>()).Decryption(this->masterkey.getHash()),
                                       Message(it.at("login").at("password").get<std::string>()));
            std::string link = Message(it.at("link").get<std::string>()).Decryption(this->masterkey.getHash());
            std::string notes = Message(it.at("notes").get<std::string>()).Decryption(this->masterkey.getHash());
            Login item(name, category, folder, loginInfo, link, notes);
            items.push_back(item);
        }

        fin.close();
    }
    // Create Vault
    Vault(const std::string &name, std::vector<unsigned char> &plain_master_key)
    {
        json newVault;

        // logic for creating the Argon2 hash
        MasterKey masterKey(plain_master_key);

        // creating the json file
        std::vector<unsigned char> hash = masterKey.getHash();
        std::vector<unsigned char> dummy = {0x64, 0x75, 0x6D, 0x6D, 0x79};
        Message encrypted_dummy(dummy, hash);

        newVault["salt"] = BinToBase64(masterKey.getSalt());
        std::vector<unsigned char> dummy_nonce = encrypted_dummy.getNonce();
        std::vector<unsigned char> dummy_message = encrypted_dummy.getEncryptedMessage();
        // store both the nonce and encryption in same structure to save up space
        std::vector<unsigned char> dummy_container;
        dummy_container.insert(dummy_container.begin(), dummy_nonce.begin(), dummy_nonce.end());
        dummy_container.insert(dummy_container.end(), dummy_message.begin(), dummy_message.end());
        newVault["dummy"] = BinToBase64(dummy_container);

        std::string path_of_vaults = std::filesystem::current_path().string();
        // Path can be changed at any time
        path_of_vaults.append("/assets/vaults/");
        // Create the .json file
        std::ofstream fout(path_of_vaults.append(name).append(".json"));
        fout << newVault.dump(4);
        fout.close();
    }
    const std::vector<Login> &getItems() const
    {
        return items;
    }
    const MasterKey &getMasterkey() const
    {
        return masterkey;
    }
};