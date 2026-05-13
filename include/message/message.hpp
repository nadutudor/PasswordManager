#pragma once
#include <iostream>
#include <vector>
#include <sodium.h>
#include "utils.hpp"
#include "../exceptions/enc_has_no_mac/enc_has_no_mac.hpp"
#include "../exceptions/master_key_mismatch_exception/master_key_mismatch_exception.hpp"
#include "../exceptions/sodium_init_failed/sodium_init_failed.hpp"
#include "../exceptions/item_value_invalid_enc/item_value_invalid_enc.hpp"
#include "../exceptions/fail_enc_message/fail_enc_message.hpp"

class Message
{
    std::vector<unsigned char> encrypted;
    // used for XChaCha20, always randomly generated; X variant is for a 24-byte nonce
    std::vector<unsigned char> nonce;
    void Encryption(const std::vector<unsigned char> &message, const std::vector<unsigned char> &hashed);

public:
    Message();
    Message(const std::vector<unsigned char> &message, const std::vector<unsigned char> &hashed);
    explicit Message(const std::string &item_value);
    friend std::ostream &operator<<(std::ostream &os, const Message &old_password);
    std::string Decryption(const std::vector<unsigned char> &hashed) const;

    const std::vector<unsigned char> &getEncryptedMessage();

    const std::vector<unsigned char> &getNonce();
};