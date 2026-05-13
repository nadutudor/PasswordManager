#include "menustate.hpp"

MenuState::~MenuState() = default;

std::unique_ptr<MenuState> MenuState::handleInput() {
    return nullptr;
}
