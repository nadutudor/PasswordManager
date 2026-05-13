#include "item_value_invalid_enc.hpp"

ItemValueInvalidEnc::ItemValueInvalidEnc() : message("Item value is not correctly encrypted \n") {}

const char* ItemValueInvalidEnc::what() const noexcept {
    return message.c_str();
}
