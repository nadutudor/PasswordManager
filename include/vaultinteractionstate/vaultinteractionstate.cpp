#include "vaultinteractionstate.hpp"

VaultInteractionState::VaultInteractionState(const std::filesystem::path &path_to_vault, const MasterKey &masterkey) : path_to_vault(path_to_vault), vault(path_to_vault, masterkey) {}

std::unique_ptr<MenuState> VaultInteractionState::doHandleInput() {
    int choice;
    std::cout << "      Options:                                 \n";
    std::cout << "  [1] Print                             \n";
    std::cout << "  [2] Insert item                              \n";
    std::cout << "  [3] Search                              \n";
    std::cout << "      [4] Return                                 \n";
    std::cin >> choice;
    switch (choice)
    {
    case 1:
        vault.print_options_vault();
        return nullptr;
    case 2:
        vault.edit_options_vault();
        return nullptr;
    case 4:
        // create unique_ptr object to VaultSelectionState
        return std::make_unique<VaultSelectionState>();
    }
    return nullptr;
}

std::unique_ptr<MenuState> VaultInteractionState::clone() const {
    auto clone = std::make_unique<VaultInteractionState>(*this);
    return clone;
}

