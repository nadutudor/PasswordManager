#include "mainmenustate.hpp"

std::unique_ptr<MenuState> MainMenuState::handleInput() {
    int choice;

    std::cout << "      Options:                                 \n";
    std::cout << "  [1] Create vault                             \n";
    std::cout << "  [2] Enter vault                              \n";
    std::cout << "      [3] Exit                                 \n";
    std::cin >> choice;
    switch (choice)
    {
    case 1:
        new Vault(); // sau Vault newVault() ? ;
        return nullptr;
    case 2:
        return std::make_unique<VaultSelectionState>();
        
    case 3:
        // exit logic in main loop
        return std::make_unique<ExitState>();
    }
    return nullptr;
}
