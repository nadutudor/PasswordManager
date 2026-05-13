#pragma once
#include <vector>
#include <iostream>
#include <sodium.h>

class MasterKey
{
    // the resulted hashed output from master key and salt
    std::vector<unsigned char> hashed;
    // used for Argon2
    std::vector<unsigned char> salt;

public:
    MasterKey();
    // for newly created masterkey
    explicit MasterKey(std::vector<unsigned char> &plain_master_key);

    // MasterKey initialization constructor
    MasterKey(const std::vector<unsigned char> &hashed, const std::vector<unsigned char> &salt);

    // for hashing the master key using an already existing salt
    [[maybe_unused]] void HashUsingExistingSalt(std::vector<unsigned char> &plain_master_key, const std::vector<unsigned char> &salt_param);

    const std::vector<unsigned char> &getHash() const;
    const std::vector<unsigned char> &getSalt() const;
};