#pragma once
#include <filesystem>
#include <memory>
#include "../vault/vault.hpp"
#include "../menustate/menustate.hpp"
#include "../vaultselectionstate/vaultselectionstate.hpp"

/*
    the state that allows the user to interact with a single vault.
*/

class VaultInteractionState : public MenuState{
    std::filesystem::path path_to_vault;
    Vault vault;

public:
    VaultInteractionState(const std::filesystem::path &path_to_vault, const MasterKey &masterkey);

    std::unique_ptr<MenuState> doHandleInput() override;
    std::unique_ptr<MenuState> clone() const override;
};