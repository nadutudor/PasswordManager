#pragma once
#include <memory>
#include <tuple>
#include <string>
#include <filesystem>
#include <vector>
#include <unordered_map>
#include "../masterkey/masterkey.hpp"
#include "../files/files.hpp"
#include "utils_vault.hpp"
#include "../vaultinteractionstate/vaultinteractionstate.hpp"
#include "../menustate/menustate.hpp"
#include "../mainmenustate/mainmenustate.hpp"

class VaultSelectionState : public MenuState {
public:
    std::unique_ptr<MenuState> doHandleInput() override;
    std::unique_ptr<MenuState> clone() const override;
};