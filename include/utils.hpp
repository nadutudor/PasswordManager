// TODO: Rewrite validate master key function

#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <sodium.h>

namespace Utils {
    std::string BinToBase64(const std::vector<unsigned char> &message);
    std::vector<unsigned char> Base64ToBin(const std::string &message);
    const std::vector<unsigned char> Enc(const std::vector<unsigned char> &plain_master_key, const std::vector<unsigned char> &salt);
    bool validate_master_key(const std::vector<unsigned char> &hashed_master_key, const std::vector<unsigned char> &dummy, const std::vector<unsigned char> &dummyNonce);
}