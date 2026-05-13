#pragma once
#include <memory>
#include <iostream>
#include "../menustate/menustate.hpp"
#include "../mainmenustate/mainmenustate.hpp"

class AboutState : public MenuState {
public:
    std::unique_ptr<MenuState> doHandleInput() override;
    std::unique_ptr<MenuState> clone() const override;
};