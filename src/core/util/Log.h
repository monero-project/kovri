/**
 * Copyright (c) 2013-2016, The Kovri I2P Router Project
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project
 */

#ifndef SRC_CORE_UTIL_LOG_H_
#define SRC_CORE_UTIL_LOG_H_

#include <iostream>
#include <memory>
#include <string>

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
 * Referencing #33.
 *
 */

enum LogLevel {
  eLogLevelDebug,
  eLogLevelInfo,
  eLogLevelWarning,
  eLogLevelError
};

#define eLogDebug i2p::util::log::eLogLevelDebug
#define eLogInfo i2p::util::log::eLogLevelInfo
#define eLogWarning i2p::util::log::eLogLevelWarning
#define eLogError i2p::util::log::eLogLevelError

class LogStreamImpl;
class LogStream : public std::ostream {
 public:
  LogStream();
  ~LogStream();

  LogStream(
      LogStreamImpl* impl);

  /// @brief Enable logging on this stream
  void Enable();

  /// @brief Disable logging on this stream
  void Disable();

  /// @brief Flush this log stream
  LogStream& Flush();

  /// @brief Check if this stream is enabled
  /// @return True if stream is enabled
  bool IsEnabled();

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
  LogStream& Warning();

  /// @return Reference to error level log stream
  LogStream& Error();

  /// @return Reference to debug level log stream
  LogStream& Debug();

  /// @brief Flush pending log events
  void Flush();

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
      std::ostream* out_stream);

  /// @brief Get global log engine
  static std::shared_ptr<Log> Get();

  /// @brief Get default logger
  std::shared_ptr<Logger> Default();

  // TODO(unassigned):
  // Uncomment when this becomes useful
  /// @brief Create a logger's given name
  //std::unique_ptr<Logger> New(
      //const std::string& name,
      //const std::string& channel);

  /// @brief Turn off logging forever
  void Stop();

  /// @brief Is logging silent right now?
  /// @return True if silent
  bool Silent();

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

void DeprecatedStartLog(
    const std::string& full_file_path);

void DeprecatedStartLog(
    std::ostream* stream);

void DeprecatedStopLog();

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

template<typename... Args>
void DeprecatedLogPrint(
    i2p::util::log::LogLevel level,
    Args... args) {
  auto logger = i2p::util::log::Log::Get();
  if (logger == nullptr) {
    // fallback logging to std::clog
    std::clog << "!!! ";
    DeprecatedLog(std::clog, args...);
    std::clog << std::endl;
  } else {
    auto log = logger->Default();
    if (level == eLogDebug) {
      auto& stream = log->Debug();
      DeprecatedLog(stream, args...);
      stream << std::flush;
    } else if (level == eLogInfo) {
      auto& stream = log->Info();
      DeprecatedLog(stream, args...);
      stream << std::flush;
    } else if (level == eLogWarning) {
      auto& stream = log->Warning();
      DeprecatedLog(stream, args...);
      stream << std::flush;
    } else  {
      auto& stream = log->Error();
      DeprecatedLog(stream, args...);
      stream << std::flush;
    }
  }
}

template<typename... Args>
void DeprecatedLogPrint(
    Args... args) {
  DeprecatedLogPrint(eLogInfo, args...);
}

#define StartLog DeprecatedStartLog
#define LogPrint DeprecatedLogPrint
#define StopLog DeprecatedStopLog

#endif  // SRC_CORE_UTIL_LOG_H_
