#pragma once
#include <memory>
#include <iostream>
#include "../exitstate/exitstate.hpp"
#include "../menustate/menustate.hpp"
#include "../vaultselectionstate/vaultselectionstate.hpp"

class MainMenuState : public MenuState {
public:
    std::unique_ptr<MenuState> doHandleInput() override;
    std::unique_ptr<MenuState> clone() const override;
};