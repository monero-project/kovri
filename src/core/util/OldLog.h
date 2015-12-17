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
void DeprecatedLog(std::ostream & s, TValue arg)
{
    s << arg;
}


template<typename TValue, typename... TArgs>
void DeprecatedLog(std::ostream & s, TValue arg, TArgs... args)
{
    DeprecatedLog(s, arg);
    DeprecatedLog(s, args...);
}


template<typename... TArgs>
void DeprecatedLogPrint(kovri::log::LogLevel level, TArgs... args)
{
    auto l = kovri::log::Log::Get();
    if (l == nullptr) {
        // fallback logging to std::clog
        std::clog << "!!! ";
        DeprecatedLog(std::clog, args...);
        std::clog << std::endl;
    } else {
        auto log = l->Default();
        if(level == eLogDebug) {
            auto & s = log->Debug();
            DeprecatedLog(s, args...);
            s << std::flush;
        } else if (level == eLogInfo) {
            auto & s = log->Info();
            DeprecatedLog(s, args...);
            s << std::flush;
        } else if(level == eLogWarning) {
            auto & s = log->Warning();
            DeprecatedLog(s, args...);
            s << std::flush;
        } else  {
            auto & s = log->Error();
            DeprecatedLog(s, args...);
            s << std::flush;
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
