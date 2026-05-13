#include "not_type_directory.hpp"

NotTypeDirectory::NotTypeDirectory(const std::string parent_directory) : message(parent_directory+ " is not a directory \n") {}

const char* NotTypeDirectory::what() const noexcept {
    return message.c_str();
}
