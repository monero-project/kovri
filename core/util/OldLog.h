#ifndef OLD_LOG_H__
#define OLD_LOG_H__
/*
  Old Logging API
 */

#include <string>
#include <sstream>
#include <iostream>

#define eLogDebug kovri::log::eLogLevelDebug
#define eLogInfo kovri::log::eLogLevelInfo
#define eLogWarning kovri::log::eLogLevelWarning
#define eLogError kovri::log::eLogLevelError


void DeprecatedStartLog (const std::string& fullFilePath);

void DeprecatedStartLog (std::ostream * s);

void DeprecatedStopLog ();

template<typename TValue>
void DeprecatedLogPrint(std::stringstream & s, TValue arg)
{
    s << arg;
}


template<typename TValue, typename... TArgs>
void DeprecatedLogPrint(std::stringstream & s, TValue arg, TArgs... args)
{
    DeprecatedLogPrint(s, arg);
    DeprecatedLogPrint(s, args...);
}


template<typename... TArgs>
void DeprecatedLogPrint(kovri::log::LogLevel level, TArgs... args)
{
    std::stringstream ss;
    DeprecatedLogPrint(ss, args...);
    auto l = kovri::log::Log::Get();
    if (l == nullptr) {
        std::clog << "!!! " << ss.str() << std::endl;
    } else {
        
        auto log = l->Default();
        switch(level)
        {
        case eLogDebug:
            log->Debug() << ss.str();
            break;
        case eLogInfo:
            log->Info() << ss.str();
            break;
        case eLogWarning:
            log->Warning() << ss.str();
            break;
        default:
            log->Error() << ss.str();
            break;
        }
    }
}

template<typename... TArgs>
void DeprecatedLogPrint (TArgs... args)
{
	DeprecatedLogPrint (eLogInfo, args...);

}
#define StopLog DeprecatedStopLog
#define StartLog DeprecatedStartLog
#define LogPrint DeprecatedLogPrint



#endif
