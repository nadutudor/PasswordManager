#include "aboutstate.hpp"

std::unique_ptr<MenuState> AboutState::doHandleInput() {
    int choice;

    std::cout << "      Object Oriented Programming Project                             \n";
    std::cout << "  Student: Nadu Tudor                             \n";
    std::cout << "  [1] Return                              \n";
    std::cin >> choice;
    switch (choice)
    {
    case 1:
        return std::make_unique<MainMenuState>();
    }
    return nullptr;
    
}

std::unique_ptr<MenuState> AboutState::clone() const {
    return std::make_unique<AboutState>(*this);
}
