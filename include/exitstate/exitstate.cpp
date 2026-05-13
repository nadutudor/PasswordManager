#include "exitstate.hpp"

std::unique_ptr<MenuState> ExitState::doHandleInput() {
    return nullptr;
}

std::unique_ptr<MenuState> ExitState::clone() const {
    return std::make_unique<ExitState>(*this);
}