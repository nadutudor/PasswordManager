#include "masterkey.hpp"

MasterKey::MasterKey() = default;

MasterKey::MasterKey(std::vector<unsigned char> &plain_master_key)
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
MasterKey::MasterKey(const std::vector<unsigned char> &hashed, const std::vector<unsigned char> &salt)
{
    this->hashed = hashed;
    this->salt = salt;
}

// for hashing the master key using an already existing salt
[[maybe_unused]] void MasterKey::HashUsingExistingSalt(std::vector<unsigned char> &plain_master_key, const std::vector<unsigned char> &salt_param)
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

const std::vector<unsigned char>& MasterKey::getHash() const
{
    return hashed;
}

const std::vector<unsigned char>& MasterKey::getSalt() const
{
    return salt;
}
