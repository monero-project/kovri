#include <boost/date_time/posix_time/posix_time.hpp>
#include "Log.h"


void DeprecatedStartLog(const std::string& fullFilePath)
{
    std::cerr << "Not opening log file: " << fullFilePath << std::endl;
}

void DeprecatedStartLog (std::ostream * s)
{
    *s << "Deprecated Logging not implemented" << std::endl;
}

void DeprecatedStopLog()
{

}
