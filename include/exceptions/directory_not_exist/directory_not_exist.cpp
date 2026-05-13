#include "directory_not_exist.hpp"

explicit DirectoryNotExist::DirectoryNotExist(const std::string parent_directory) : message(parent_directory+ " does not exist \n") {}

const char* DirectoryNotExist::what() const noexcept {
    return message.c_str();
}
