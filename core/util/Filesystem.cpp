#include "Filesystem.h"

namespace i2p {
namespace util {
namespace filesystem {

std::string appName("kovri");

void SetAppName(const std::string& name)
{
    appName = name;
}

std::string GetAppName()
{
    return appName;
}

boost::filesystem::path GetDefaultDataDir()
{
    // Custom path, or default path:
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\kovri
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\kovri
    // Mac: ~/Library/Application Support/kovri
    // Unix: ~/.kovri
#ifdef KOVRI_CUSTOM_DATA_PATH
    return boost::filesystem::path(std::string(KOVRI_CUSTOM_DATA_PATH));
#else
#ifdef _WIN32
    // Windows
    char localAppData[MAX_PATH];
    SHGetFolderPath(NULL, CSIDL_APPDATA, 0, NULL, localAppData);
    return boost::filesystem::path(std::string(localAppData) + "\\" + appName);
#else
    boost::filesystem::path pathRet;
    char* pszHome = getenv("HOME");
    if(pszHome == NULL || strlen(pszHome) == 0)
        pathRet = boost::filesystem::path("/");
    else
        pathRet = boost::filesystem::path(pszHome);
#ifdef __APPLE__
    // Mac
    pathRet /= "Library/Application Support";
    boost::filesystem::create_directory(pathRet);
    return pathRet / appName;
#else
    // Unix
    return pathRet / (std::string (".") + appName);
#endif
#endif
#endif
}

const boost::filesystem::path& GetDataDir()
{
    static boost::filesystem::path path;

    path = GetDefaultDataDir();

    if(!boost::filesystem::exists(path)) {
        // Create data directory
        if(!boost::filesystem::create_directory(path)) {
            LogPrint("Failed to create data directory!");
            path = "";
            return path;
        }
    }
    if(!boost::filesystem::is_directory(path))
        path = GetDefaultDataDir();
    return path;
}

std::string GetFullPath(const std::string& filename)
{
    std::string fullPath = GetDataDir().string();
#ifndef _WIN32
    fullPath.append("/");
#else
    fullPath.append("\\");
#endif
    fullPath.append(filename);
    return fullPath;
}

boost::filesystem::path GetConfigFile()
{
    boost::filesystem::path pathConfigFile(
        i2p::util::config::varMap["config"].as<std::string>()
    );
    if(!pathConfigFile.is_complete())
        pathConfigFile = GetDataDir() / pathConfigFile;
    return pathConfigFile;
}

boost::filesystem::path GetTunnelsConfigFile()
{
    boost::filesystem::path pathTunnelsConfigFile(
        i2p::util::config::varMap["tunnelscfg"].as<std::string>()
    );
    if(!pathTunnelsConfigFile.is_complete())
        pathTunnelsConfigFile = GetDataDir() / pathTunnelsConfigFile;
    return pathTunnelsConfigFile;
}

} // filesystem
} // util
} // i2p
