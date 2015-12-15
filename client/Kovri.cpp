#include <thread>
#include <stdlib.h>
#include "Daemon.h"
#include "util/Config.h"
#include "util/Log.h"

int main(int argc, char* argv[])
{
    try {
	if(i2p::util::config::ParseArgs(argc, argv) == 1)
	    return EXIT_FAILURE;
    } catch(const std::exception& ex) {
	std::cout << ex.what() << "\nTry using --help" << std::endl;
        return EXIT_FAILURE;
    }

    if(!Daemon.Init())
        return EXIT_FAILURE;

    if(Daemon.Start()) {
        while (Daemon.m_isRunning) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    Daemon.Stop();
    return EXIT_SUCCESS;
}
