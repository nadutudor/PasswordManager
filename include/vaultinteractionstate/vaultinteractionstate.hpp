#pragma once
#include <filesystem>
#include <memory>
#include "../vault/vault.hpp"
#include "../menustate/menustate.hpp"
#include "../vaultselectionstate/vaultselectionstate.hpp"

class VaultInteractionState : public MenuState{
    std::filesystem::path path_to_vault;
    Vault vault;

public:
    VaultInteractionState(const std::filesystem::path &path_to_vault, const MasterKey &masterkey);

    std::unique_ptr<MenuState> handleInput() override;
};