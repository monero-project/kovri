#include "Filesystem.h"

namespace i2p {
namespace util {
namespace filesystem {

using namespace std;
using namespace boost::filesystem;

string appName("kovri");

void SetAppName(const string& name)
{
    appName = name;
}

string GetAppName()
{
    return appName;
}

path GetConfigFile()
{
    path pathConfigFile(
        i2p::util::config::varMap["config"].as<string>()
    );
    if(!pathConfigFile.is_complete())
        pathConfigFile = GetDataPath() / pathConfigFile;
    return pathConfigFile;
}

path GetTunnelsConfigFile()
{
    path pathTunnelsConfigFile(
        i2p::util::config::varMap["tunnelscfg"].as<string>()
    );
    if(!pathTunnelsConfigFile.is_complete())
        pathTunnelsConfigFile = GetDataPath() / pathTunnelsConfigFile;
    return pathTunnelsConfigFile;
}

path GetSU3CertsPath()
{
    return GetDataPath() / "resources" / "certificates" / "su3";
}

path GetSSLCertsPath()
{
    return GetDataPath() / "resources" / "certificates" / "ssl";
}

string GetFullPath(const string& filename)
{
    string fullPath = GetDataPath().string();
#ifdef _WIN32
    fullPath.append("\\");
#else
    fullPath.append("/");
#endif
    fullPath.append(filename);
    return fullPath;
}

const path& GetDataPath()
{
    static path path;

    path = GetDefaultDataPath();

    if(!exists(path)) {
        // Create data directory
        if(!create_directory(path)) {
            LogPrint("Failed to create data directory!");
            path = "";
            return path;
        }
    }
    if(!is_directory(path))
        path = GetDefaultDataPath();
    return path;
}

path GetDefaultDataPath()
{
    // Custom path, or default path:
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\kovri
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\kovri
    // Mac: ~/Library/Application Support/kovri
    // Unix: ~/.kovri
#ifdef KOVRI_CUSTOM_DATA_PATH
    return path(string(KOVRI_CUSTOM_DATA_PATH));
#else
#ifdef _WIN32
    // Windows
    char localAppData[MAX_PATH];
    SHGetFolderPath(NULL, CSIDL_APPDATA, 0, NULL, localAppData);
    return path(string(localAppData) + "\\" + appName);
#else
    path pathRet;
    char* home = getenv("HOME");
    if(home == NULL || strlen(home) == 0)
        pathRet = path("/");
    else
        pathRet = path(home);
#ifdef __APPLE__
    // Mac
    pathRet /= "Library/Application Support";
    create_directory(pathRet);
    return pathRet / appName;
#else
    // Unix
    return pathRet / (string (".") + appName);
#endif
#endif
#endif
}

} // filesystem
} // util
} // i2p
