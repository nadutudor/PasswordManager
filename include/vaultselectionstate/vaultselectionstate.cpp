#include "vaultselectionstate.hpp"

std::unique_ptr<MenuState> VaultSelectionState::doHandleInput() {
    int choice;
    std::tuple<std::string, MasterKey> result;
    std::string path_of_vaults = std::filesystem::current_path().string();
    // Path can be changed at any time
    path_of_vaults.append("/assets/vaults/");
    Files file(path_of_vaults);
    const auto& paths_vault_index = file.getPaths();
    const std::unordered_map<std::filesystem::path, std::array<std::vector<unsigned char>, 3>>& paths = paths_vault_index.getPaths();
    
    std::cout << "      Options:                                 \n";
    std::cout << "  [1] Find vault                             \n";
    std::cout << "  [2] Enter vault name                              \n";
    std::cout << "      [3] Return                                 \n";
    std::cin >> choice;
    switch (choice)
    {
    case 1:
        UtilsVault::find_vault(paths);
        return nullptr;
    case 2:
        result = UtilsVault::known_vault(paths, path_of_vaults);
        if(std::get<0>(result) == "")
            return nullptr;
        return std::make_unique<VaultInteractionState>(std::get<0>(result), std::get<1>(result));
    case 3:
        return std::make_unique<MainMenuState>();
    }
    return nullptr;
}

std::unique_ptr<MenuState> VaultSelectionState::clone() const {
    return std::make_unique<VaultSelectionState>(*this);
}