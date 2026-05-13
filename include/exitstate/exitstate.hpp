#pragma once
#include <memory>
#include "../menustate/menustate.hpp"

class ExitState : public MenuState {
    public:
    std::unique_ptr<MenuState> doHandleInput() override;
    std::unique_ptr<MenuState> clone() const override;
};