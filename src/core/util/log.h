/**                                                                                           //
 * Copyright (c) 2013-2016, The Kovri I2P Router Project                                      //
 *                                                                                            //
 * All rights reserved.                                                                       //
 *                                                                                            //
 * Redistribution and use in source and binary forms, with or without modification, are       //
 * permitted provided that the following conditions are met:                                  //
 *                                                                                            //
 * 1. Redistributions of source code must retain the above copyright notice, this list of     //
 *    conditions and the following disclaimer.                                                //
 *                                                                                            //
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list     //
 *    of conditions and the following disclaimer in the documentation and/or other            //
 *    materials provided with the distribution.                                               //
 *                                                                                            //
 * 3. Neither the name of the copyright holder nor the names of its contributors may be       //
 *    used to endorse or promote products derived from this software without specific         //
 *    prior written permission.                                                               //
 *                                                                                            //
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY        //
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF    //
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL     //
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,       //
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,               //
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    //
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,          //
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF    //
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.               //
 *                                                                                            //
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project          //
 */

#ifndef SRC_CORE_UTIL_LOG_H_
#define SRC_CORE_UTIL_LOG_H_

#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace i2p {
namespace util {
namespace log {

/**
 *
 * Our flow is as follows (see Boost.Log):
 *
 * Kovri -> LogStream -> Logger -> Log -> UI
 *
 * =========================================
 *
 * TODO(unassigned):
 * Our current logging implementation is overwritten and convoluted.
 * Our flow pattern is sound but a pimpl design for LogStream, Logger,
 * and Log, serves no useful purpose (though *may* in the future).
 * It should also be noted that to effectively remove deprecations,
 * a design rewrite is necessary.
 *
 * Referencing #223
 *
 */

enum LogLevel {
  eLogLevelDebug,
  eLogLevelInfo,
  eLogLevelWarn,
  eLogLevelError
};

#define eLogDebug i2p::util::log::eLogLevelDebug
#define eLogInfo i2p::util::log::eLogLevelInfo
#define eLogWarn i2p::util::log::eLogLevelWarn
#define eLogError i2p::util::log::eLogLevelError

/// @typedef LogLevelsMap
/// @brief Map of log levels
typedef std::unordered_map<std::string, LogLevel> LogLevelsMap;

/// @brief Set log levels/severity
void SetGlobalLogLevels(
    const std::vector<std::string>& levels);

/// @brief Get log levels/severity
/// @return Log levels/severity
const LogLevelsMap& GetGlobalLogLevels();

/// @brief Sets console logging option
/// @param option Option set from configuration
void SetOptionLogToConsole(
    bool option);

/// @brief Gets console logging option
bool GetOptionLogToConsole();

/// @brief Sets file logging option
/// @param option Option set from configuration
void SetOptionLogToFile(
    bool option);

/// @brief Gets file logging option
bool GetOptionLogToFile();

/// @brief Sets log filename
/// @param option Option set from configuration
void SetOptionLogFileName(
    const std::string& option);

/// @brief Gets log filename option
const std::string& GetOptionLogFileName();

class LogStreamImpl;
class LogStream : public std::ostream {
 public:
  LogStream();
  ~LogStream();

  LogStream(
      LogStreamImpl* impl);

 private:
  std::unique_ptr<LogStreamImpl> m_LogStreamPimpl;
};

class LoggerImpl;
class Logger {
 public:
  Logger();
  ~Logger();

  Logger(
      LoggerImpl* impl);

  /// @return Reference to info level log stream
  LogStream& Info();

  /// @return Reference to warning level log stream
  LogStream& Warn();

  /// @return Reference to error level log stream
  LogStream& Error();

  /// @return Reference to debug level log stream
  LogStream& Debug();

 private:
  std::unique_ptr<LoggerImpl> m_LoggerPimpl;
};

class LogImpl;
class Log {
 public:
  Log();
  ~Log();

  Log(
      LogLevel min_level,
      std::ostream* out_stream,
      const std::string& log_file_name);

  /// @brief Gets global log engine
  /// @return Shared pointer to global log engine
  static std::shared_ptr<Log> GetGlobalLogEngine();

  /// @brief Gets default logger
  /// @return Shared pointer to default logger
  std::shared_ptr<Logger> GetDefaultLogger();

 private:
  std::shared_ptr<LogImpl> m_LogPimpl;
  std::shared_ptr<Logger> m_DefaultLogger;
};

}  // namespace log
}  // namespace util
}  // namespace i2p

/**
 *
 * Deprecated Logger
 *
 */

template<typename Arg>
void DeprecatedLog(
    std::ostream& stream,
    Arg arg) {
  stream << arg;
}

template<typename Value, typename... Args>
void DeprecatedLog(
    std::ostream& stream,
    Value arg,
    Args... args) {
  DeprecatedLog(stream, arg);
  DeprecatedLog(stream, args...);
}

// TODO(unassigned): more efficient way to execute this function.
template<typename... Args>
void DeprecatedLogPrint(
    i2p::util::log::LogLevel level,
    Args... args) {
  auto logger = i2p::util::log::Log::GetGlobalLogEngine();
  if (!logger) {
    // fallback logging to std::clog
    DeprecatedLog(std::clog, args...);
    std::clog << std::endl;
    return;
  }
  // Set log implementation
  auto log = logger->GetDefaultLogger();
  if (!log) {
    // Logger disabled by user options
    return;
  }
  // Get global log levels
  auto global_levels = i2p::util::log::GetGlobalLogLevels();
  // Print log after testing arg level against global levels
  if (level == eLogDebug) {
    for (auto& current_level : global_levels) {
      if (current_level.second == eLogDebug) {
        auto& stream = log->Debug();
        DeprecatedLog(stream, args...);
        stream << std::flush;
      }
    }
  } else if (level == eLogInfo) {
    for (auto& current_level : global_levels) {
      if (current_level.second == eLogInfo) {
        auto& stream = log->Info();
        DeprecatedLog(stream, args...);
        stream << std::flush;
      }
    }
  } else if (level == eLogWarn) {
    for (auto& current_level : global_levels) {
      if (current_level.second == eLogWarn) {
        auto& stream = log->Warn();
        DeprecatedLog(stream, args...);
        stream << std::flush;
      }
    }
  } else if (level == eLogError) {
    for (auto& current_level : global_levels)  {
      if (current_level.second == eLogError) {
        auto& stream = log->Error();
        DeprecatedLog(stream, args...);
        stream << std::flush;
      }
    }
  }
}

template<typename... Args>
void DeprecatedLogPrint(
    Args... args) {
  DeprecatedLogPrint(eLogInfo, args...);
}

#define LogPrint DeprecatedLogPrint

#endif  // SRC_CORE_UTIL_LOG_H_
