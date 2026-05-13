#pragma once
#include <memory>

class MenuState{
public:
    virtual ~MenuState();

    // if nullptr, stay in the current state, else return new state
    virtual std::unique_ptr<MenuState> handleInput();
};