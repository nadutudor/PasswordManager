#pragma once
#include <memory>

class MenuState{
public:
    virtual ~MenuState();

    /* for non-virtual interface pattern. handleInput() wrapper for doHandleInput(). 
    handleInput might be used by all derived classes, but not doHandleInput which is class specific*/
    std::unique_ptr<MenuState> handleInput();

    virtual std::unique_ptr<MenuState> clone() const = 0;

protected:
    // if nullptr, stay in the current state, else return new state
    virtual std::unique_ptr<MenuState> doHandleInput() = 0;
};