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
    /**
     * Change the application name.
     */
    void SetAppName(const std::string& name);

    /**
     * @return the application name.
     */
    std::string GetAppName();

    /**
     * @return the default directory for app data
     */
    boost::filesystem::path GetDefaultDataDir();

    /**
     * @return the path of the kovri directory
     */
    const boost::filesystem::path& GetDataDir();

    /**
     * @return the full path of a file within the kovri directory
     */
    std::string GetFullPath(const std::string& filename);

    /**
     * @return the path of the configuration file
     */
    boost::filesystem::path GetConfigFile();

    /**
     * @return the path of the tunnels configuration file
     */
    boost::filesystem::path GetTunnelsConfigFile();

    /**
     * Read a configuration file and store its contents in the given maps.
     */
    void ReadConfigFile(std::map<std::string, std::string>& mapSettingsRet,
         std::map<std::string, std::vector<std::string> >& mapMultiSettingsRet);

} // filesystem
} // util
} // i2p


#endif