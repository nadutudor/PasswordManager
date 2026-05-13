#pragma once
#include <memory>
#include "../menustate/menustate.hpp"

class ExitState : public MenuState {
    public:
    std::unique_ptr<MenuState> handleInput() override;
};