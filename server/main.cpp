// main.cpp
#include "Communicator.h"
#include "OutputManager.h"


int main() {
    Communicator communicator;

    communicator.bindAndListen();
    communicator.StartCommunication();


    return 0;
}
