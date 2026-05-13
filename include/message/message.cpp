#include "message.hpp"

void Message::Encryption(const std::vector<unsigned char> &message, const std::vector<unsigned char> &hashed)
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

Message::Message() = default;

Message::Message(const std::vector<unsigned char> &message, const std::vector<unsigned char> &hashed)
{
    Encryption(message, hashed);
}

Message::Message(const std::string &item_value)
{
    std::vector<unsigned char> binary_item_value = Utils::Base64ToBin(item_value);
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

std::ostream &operator<<(std::ostream &os, const Message &old_password)
{
    for (const unsigned char &t : old_password.encrypted)
        os << t;
    return os << " \n";
}

std::string Message::Decryption(const std::vector<unsigned char> &hashed) const
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

const std::vector<unsigned char> & Message::getEncryptedMessage()
{
    return encrypted;
}

const std::vector<unsigned char> & Message::getNonce()
{
    return nonce;
}
