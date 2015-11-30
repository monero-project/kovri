#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <iostream>
#include <boost/filesystem/fstream.hpp>
#include <boost/program_options.hpp>
#include "core/Version.h"
#include "Filesystem.h"

namespace i2p {
namespace util {
namespace config {

    // Our configuration files
    extern std::string kovriConfig, tunnelsConfig;

    // Config option descriptions
    extern boost::program_options::options_description confOpts;

    // Variable map for CLI and conf args
    extern boost::program_options::variables_map varMap;

    /**
     * Note: CLI args override config file args but
     * args that are not overridden will stay mapped
     */
    void ParseConfigFile(std::string& kovriConfig,
        boost::program_options::options_description& confOpts,
	boost::program_options::variables_map& varMap);

    /**
     * @return 1 on failure/help, 0 on success
     */
    bool ParseArgs(int argc, char* argv[]);

}
}
}

#endif
