#include "statemanager.hpp"

StateManager::StateManager(std::unique_ptr<MenuState> currentState) : currentState(std::move(currentState)) {}
void StateManager::run() {
    bool running = true;

    while(running && currentState != nullptr){
        // making the transition to the next state (can be the same as currentstate)
        std::unique_ptr<MenuState> nextState = currentState->handleInput();

        if(nextState != nullptr && dynamic_cast<ExitState*>(nextState.get()) == nullptr){

            /* since pointers are unique_ptr, there can't be two pointing at the same object, so object of currentState is deleted, currenState
            points to object in nextState and nextState becomes nullptr*/
            currentState = std::move(nextState);
        }
        else if(dynamic_cast<ExitState*>(nextState.get()) != nullptr)
            running = false;
    }
}

StateManager& StateManager::operator=(const StateManager &app){
    if(this == &app)
        return *this;
    
    currentState = app.currentState->clone();

    return *this;
}