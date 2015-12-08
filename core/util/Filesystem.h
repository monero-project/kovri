#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <map>
#include <string>
#include <set>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include "Log.h"
#include "Config.h"

/**
 * Fixes undefined reference to boost::filesystem::detail::copy_file
 * See https://github.com/purplei2p/i2pd/issues/272
 */
#define BOOST_NO_CXX11_SCOPED_ENUMS

namespace i2p {
namespace util {
namespace filesystem {

    using namespace std;
    using namespace boost::filesystem;

    /**
     * Change the application name.
     */
    void SetAppName(const string& name);

    // @return the application name.
    string GetAppName();

    // @return the full path of a file within the kovri directory
    string GetFullPath(const string& filename);

    // @return the path of the configuration file
    path GetConfigFile();

    // @return the path of the tunnels configuration file
    path GetTunnelsConfigFile();

    // @return the path to certificates for SU3 verification
    path GetSU3CertsPath();

    // @return the path to SSL certificates for TLS/SSL negotiation
    path GetSSLCertsPath();

    // @return the path of the kovri directory
    const path& GetDataPath();

    // @return the default directory for app data
    path GetDefaultDataPath();

} // filesystem
} // util
} // i2p

#endif