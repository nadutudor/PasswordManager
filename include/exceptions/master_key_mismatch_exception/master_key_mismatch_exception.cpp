#include "master_key_mismatch_exception.hpp"

MasterKeyMismatchException::MasterKeyMismatchException() : message("Masterkey doesn't match \n") {}

const char* MasterKeyMismatchException::what() const noexcept {
    return message.c_str();
}
