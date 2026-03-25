#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <sodium.h>

using json = nlohmann::json;

std::string Bin2Base64(const std::vector<unsigned char> &message)
{
    size_t encoded_len = sodium_base64_ENCODED_LEN(message.size(), sodium_base64_VARIANT_ORIGINAL);

    std::string base64_buffer(encoded_len, '\0');
    sodium_bin2base64(&base64_buffer[0], encoded_len, message.data(), message.size(), sodium_base64_VARIANT_ORIGINAL);

    if (base64_buffer.back() == '\0')
        base64_buffer.pop_back();

    return base64_buffer;
}

std::vector<unsigned char> Base642Bin(const std::string &message)
{
    std::vector<unsigned char> raw_binary(message.length());
    size_t bin_len;

    sodium_base642bin(raw_binary.data(), raw_binary.size(), message.data(), message.length(),
                      nullptr, &bin_len, nullptr, sodium_base64_VARIANT_ORIGINAL);

    raw_binary.resize(bin_len);
    return raw_binary;
}

const std::vector<unsigned char> Enc(const std::vector<unsigned char> &plain_master_key, const std::vector<unsigned char> &salt)
{
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium \n";
        return std::vector<unsigned char>();
    }

    // creating the hash
    std::vector<unsigned char> hashed_output(32);

    int result = crypto_pwhash(hashed_output.data(), hashed_output.size(), reinterpret_cast<const char *>(plain_master_key.data()), plain_master_key.size(), salt.data(),
                  crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_ARGON2ID13);
    if(result){
        std::cerr << "Failed to encrypt the message \n";
        return std::vector<unsigned char>();
    }
    return hashed_output;
}

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
        std::vector<unsigned char> binary_item_value = Base642Bin(item_value);
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

        if(result){
            std::cerr<<"Failed to hash the master key \n";
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
        if(result){
            std::cerr<<"Failed to hash the master key \n";
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
            std::vector<unsigned char> dummy_bin_container = Base642Bin(vault["dummy"]);
            std::vector<unsigned char> dummy_bin;
            dummy_bin.insert(dummy_bin.begin(), dummy_bin_container.begin() + 24, dummy_bin_container.end());
            std::vector<unsigned char> dummy_nonce_bin;
            dummy_nonce_bin.insert(dummy_nonce_bin.begin(), dummy_bin_container.begin(), dummy_bin_container.begin() + 24);
            paths[file.path()][0] = Base642Bin(salt_b64);
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

class Category
{
    std::string name;

public:
    Category() = default;
    explicit Category(const std::string &name) : name{name} {}
    explicit Category(const Category &old_category) : name{old_category.name}{}
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
          const std::string &notes) : item_name{item_name}, category{category}, folder{folder}, loginInfo{loginInfo}, link{link}, notes{notes}{}
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

        newVault["salt"] = Bin2Base64(masterKey.getSalt());
        std::vector<unsigned char> dummy_nonce = encrypted_dummy.getNonce();
        std::vector<unsigned char> dummy_message = encrypted_dummy.getEncryptedMessage();
        // store both the nonce and encryption in same structure to save up space
        std::vector<unsigned char> dummy_container;
        dummy_container.insert(dummy_container.begin(), dummy_nonce.begin(), dummy_nonce.end());
        dummy_container.insert(dummy_container.end(), dummy_message.begin(), dummy_message.end());
        newVault["dummy"] = Bin2Base64(dummy_container);

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

// std::string password_gen(){

// }

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
    Vault newVault(vaultName, plain_master_key);
}

bool validate_master_key(const std::vector<unsigned char> &hashed_master_key, const std::vector<unsigned char> &dummy, const std::vector<unsigned char> &dummyNonce)
{
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialize libsodium \n";
        return false;
    }
    // check if the encryption even has the MAC tag
    if (dummy.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
    {
        std::cerr << "Encryption doesn't have MAC tag \n";
        return false;
    }

    std::vector<unsigned char> decrypted(dummy.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long decrypted_len;

    int result = crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted.data(), &decrypted_len, nullptr, dummy.data(), dummy.size(),
                                                            nullptr, 0, dummyNonce.data(), hashed_master_key.data());
    if (result)
    {
        return false;
    }

    return true;
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

    // int choice;
    // bool running = true;
    // while(running){
    //     std::cout<<"      Options:                                 \n";
    //     std::cout<<"  [1] Print all data                             \n";
    //     std::cout<<"  [2] Search item name                              \n";
    //     std::cout<<"      [3] Return                                 \n";
    //     std::cin>>choice;
    //     switch(choice){
    //         case 1:
    //             print_options_vault(vault);
    //             break;
    //         case 2:
    //             edit_options_vault(vault);
    //             break;
    //         case 3:
    //             running = false;
    //             break;
    //     }
    // }
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

        return Bin2Base64(container);
    };

    // 1. Read the existing vault file from disk
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

    // 2. Create the new encrypted JSON object
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

    // 3. Append the new item and overwrite the JSON file
    vault_json["items"].push_back(new_item);

    std::ofstream fout(path_to_vault);
    fout << vault_json.dump(4);
    fout.close();

    std::cout << "\n  Item successfully encrypted and saved to vault!\n";
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