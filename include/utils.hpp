// TODO: Rewrite validate master key function

#pragma once
#include <string>
#include <vector>
#include <sodium.h>


std::string BinToBase64(const std::vector<unsigned char> &message)
{
    size_t encoded_len = sodium_base64_ENCODED_LEN(message.size(), sodium_base64_VARIANT_ORIGINAL);

    std::string base64_buffer(encoded_len, '\0');
    sodium_bin2base64(&base64_buffer[0], encoded_len, message.data(), message.size(), sodium_base64_VARIANT_ORIGINAL);

    if (base64_buffer.back() == '\0')
        base64_buffer.pop_back();

    return base64_buffer;
}

std::vector<unsigned char> Base64ToBin(const std::string &message)
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
    if (result)
    {
        std::cerr << "Failed to encrypt the message \n";
        return std::vector<unsigned char>();
    }
    return hashed_output;
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