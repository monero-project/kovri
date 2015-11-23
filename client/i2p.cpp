#include <thread>
#include <stdlib.h>
#include "Daemon.h"
#include "Reseed.h"

int main(int argc, char* argv[])
{
    if(!Daemon.init(argc, argv))
        return EXIT_FAILURE;

    if(Daemon.start()) {
        while (Daemon.running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    Daemon.stop();
    return EXIT_SUCCESS;
}
