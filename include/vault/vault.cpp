#include "vault.hpp"


// For an already existing vault
Vault::Vault(const std::filesystem::path &existing_vault, const MasterKey &masterkey) : masterkey{masterkey}
{
    json vault;
    std::ifstream fin(existing_vault);
    try {
        if (!fin.is_open())
            throw FailedOpenVault();
    }
    catch(const FailedOpenVault &e){
        std::cerr<<e.what();
        return;
    }

    try {
        try{
            fin >> vault;
        }
        catch (const json::parse_error &){
            throw VaultInvalidJSON(existing_vault.string());
        }
    }
    catch(const VaultInvalidJSON &e) {
        std::cerr<<e.what();
        return;
    }

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
    path_to_vault = existing_vault;
}

// Create Vault
Vault::Vault()
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
    
    json newVault;

    // logic for creating the Argon2 hash
    MasterKey masterKey(plain_master_key);

    // creating the json file
    std::vector<unsigned char> hash = masterKey.getHash();
    std::vector<unsigned char> dummy = {0x64, 0x75, 0x6D, 0x6D, 0x79};
    Message encrypted_dummy(dummy, hash);

    newVault["salt"] = Utils::BinToBase64(masterKey.getSalt());
    std::vector<unsigned char> dummy_nonce = encrypted_dummy.getNonce();
    std::vector<unsigned char> dummy_message = encrypted_dummy.getEncryptedMessage();
    // store both the nonce and encryption in same structure to save up space
    std::vector<unsigned char> dummy_container;
    dummy_container.insert(dummy_container.begin(), dummy_nonce.begin(), dummy_nonce.end());
    dummy_container.insert(dummy_container.end(), dummy_message.begin(), dummy_message.end());
    newVault["dummy"] = Utils::BinToBase64(dummy_container);

    std::filesystem::path path_of_vaults = std::filesystem::current_path() / "assets" / "vaults";
    std::filesystem::create_directories(path_of_vaults);
    std::ofstream fout(path_of_vaults / (vaultName + ".json"));
    fout << newVault.dump(4);
    fout.close();
    path_to_vault = path_of_vaults / (vaultName + ".json");
}

const std::vector<Login>& Vault::getItems() const
{
    return items;
}

const MasterKey& Vault::getMasterkey() const
{
    return masterkey;
}

void Vault::print_options_vault()
{
    for (const Login &item : items)
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
        std::cout << "\t\t" << "Password: " << item.getLoginInfo().getPassword().Decryption(masterkey.getHash()) << " \n\n\n\n";
    }
}

void Vault::edit_options_vault()
{
    std::string name, category, folder, link, notes, username, password;

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
        Message msg(plain, masterkey.getHash());

        std::vector<unsigned char> nonce = msg.getNonce();
        std::vector<unsigned char> cipher = msg.getEncryptedMessage();

        std::vector<unsigned char> container;
        container.reserve(nonce.size() + cipher.size());
        container.insert(container.end(), nonce.begin(), nonce.end());
        container.insert(container.end(), cipher.begin(), cipher.end());

        return Utils::BinToBase64(container);
    };

    // Read the existing vault file from disk
    std::ifstream fin(path_to_vault);
    json vault_json;
    try {
        if(fin.is_open()){
            fin >> vault_json;
            fin.close();
        }
        else
            throw FailedOpenVaultEdit();
    }
    catch(const FailedOpenVaultEdit &e) {
        std::cerr<<e.what();
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