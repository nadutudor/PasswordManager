#pragma once
#include <memory>
#include "../menustate/menustate.hpp"

/*
    the state that marks the termination of the application.
*/

class ExitState : public MenuState {
    public:
    std::unique_ptr<MenuState> doHandleInput() override;
    std::unique_ptr<MenuState> clone() const override;
};