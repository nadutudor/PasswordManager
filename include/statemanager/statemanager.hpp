#pragma once
#include <memory>
#include "../menustate/menustate.hpp"
#include "../exitstate/exitstate.hpp"

class StateManager {
    std::unique_ptr<MenuState> currentState;
public:
    explicit StateManager(std::unique_ptr<MenuState> currentState);
    void run();
    StateManager &operator=(const StateManager &app);
};