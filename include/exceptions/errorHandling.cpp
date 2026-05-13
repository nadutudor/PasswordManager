#include <iostream>
#include <exception>
#include <filesystem>


// class MasterKeyMismatchException : public std::exception {
//     std::string message;
// public:
//     MasterKeyMismatchException() : message("Masterkey doesn't match \n") {}

//     virtual const char* what() const noexcept override {
//         return message.c_str();
//     }
// };


class DirectoryNotExist : public std::exception {
    std::string message;
public:
    explicit DirectoryNotExist(const std::string parent_directory) : message(parent_directory+ " does not exist \n") {}

    virtual const char* what() const noexcept override {
        return message.c_str();
    }
};

class NotTypeDirectory : public std::exception {
    std::string message;
public:
    explicit NotTypeDirectory(const std::string parent_directory) : message(parent_directory+ " is not a directory \n") {}

    virtual const char* what() const noexcept override {
        return message.c_str();
    }
};

