#include "mainmenustate.hpp"

std::unique_ptr<MenuState> MainMenuState::doHandleInput() {
    int choice;

    std::cout << "      Options:                                 \n";
    std::cout << "  [1] Create vault                             \n";
    std::cout << "  [2] Enter vault                              \n";
    std::cout << "  [3] About                              \n";
    std::cout << "      [4] Exit                                 \n";
    std::cin >> choice;
    switch (choice)
    {
    case 1:
        new Vault();
        return nullptr;
    case 2:
        return std::make_unique<VaultSelectionState>();
    case 3:
        return std::make_unique<AboutState>();
    case 4:
        // exit logic in main loop
        return std::make_unique<ExitState>();
    }
    return nullptr;
}

std::unique_ptr<MenuState> MainMenuState::clone() const {
    return std::make_unique<MainMenuState>(*this);
}
