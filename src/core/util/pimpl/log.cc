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

#include "core/util/log.h"

#include <boost/core/null_deleter.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/log/attributes.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>

#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace i2p {
namespace util {
namespace log {

/**
 *
 * Configuration/command-line options
 *
 * TODO(unassigned): Get/Set are not ideal here.
 * See #96, #98, and #223
 *
 */

/// @var g_LogLevels
/// @brief Maps string global levels to enumerated global levels
LogLevelsMap g_LogLevels {
  { "info", eLogInfo },
  { "warn", eLogWarn },
  { "error", eLogError },
  { "debug", eLogDebug },
};

/// @brief Sets global log levels with sanitized user input
/// @param levels String vector of user-supplied log levels
void SetGlobalLogLevels(
    const std::vector<std::string>& levels) {
  // Create temporary map for new global levels
  LogLevelsMap new_levels;
  // Iterate and insert into new global map
  for (auto& v : levels) {
    auto key = g_LogLevels.find(v);
    if (key != g_LogLevels.end())
      new_levels.insert({v, g_LogLevels[v]});
  }
  // Set new global map
  g_LogLevels.swap(new_levels);
}

/// @brief Returns current state of global log levels
const LogLevelsMap& GetGlobalLogLevels() {
  return g_LogLevels;
}

/// @var g_EnableLogToConsole
/// @brief Global log to console option
/// @notes Must be initialized by config options
bool g_EnableLogToConsole;

/// @var g_EnableLogToFile
/// @brief Global log to file option
/// @notes Must be initialized by config options
bool g_EnableLogToFile;

/// @var g_LogFileName
/// @brief Global log filename
std::string g_LogFileName;

/// @brief Sets console logging option
/// @param option Option set from configuration
void SetOptionLogToConsole(
    bool option) {
  g_EnableLogToConsole = option;
}

/// @brief Gets console logging option
bool GetOptionLogToConsole() {
  return g_EnableLogToConsole;
}

/// @brief Sets file logging option
/// @param option Option set from configuration
void SetOptionLogToFile(
    bool option) {
  g_EnableLogToFile = option;
}

/// @brief Gets file logging option
bool GetOptionLogToFile() {
  return g_EnableLogToFile;
}

/// @brief Sets log filename
/// @param option Option set from configuration
void SetOptionLogFileName(
    const std::string& option) {
  g_LogFileName = option;
}

/// @brief Gets log filename option
const std::string& GetOptionLogFileName() {
  return g_LogFileName;
}

/**
 *
 * ostream backend + sink
 *
 */

/// @typedef ostream_backend_t
/// @brief Boost.Log text ostream backend sink
typedef boost::log::sinks::text_ostream_backend ostream_backend_t;

/// @typedef ostream_backend_ptr
/// @brief Shared pointer to ostream backend sink
typedef boost::shared_ptr<ostream_backend_t> ostream_backend_ptr;

/// @typedef ostream_sink_t
/// @brief Boost.Log asynchronous ostream sink
typedef boost::log::sinks::asynchronous_sink<ostream_backend_t> ostream_sink_t;

/// @typedef ostream_sink_ptr
/// @brief Shared pointer to ostream sink
typedef boost::shared_ptr<ostream_sink_t> ostream_sink_ptr;

/// @var g_LogOutStreamSink
/// @brief sink pointer to global log ostream sink
ostream_sink_ptr g_LogOutStreamSink;

/**
 *
 * File backend + sink
 *
 */

/// @typedef backend_t
/// @brief Boost.Log text file backend sink
typedef boost::log::sinks::text_file_backend file_backend_t;

/// @typedef file_backend_ptr
/// @brief Shared pointer to backend sink
typedef boost::shared_ptr<file_backend_t> file_backend_ptr;

/// @typedef file_sink_t
/// @brief Boost.Log asynchronous file sink
typedef boost::log::sinks::asynchronous_sink<file_backend_t> file_sink_t;

/// @typedef file_sink_ptr
/// @brief Shared pointer to file sink
typedef boost::shared_ptr<file_sink_t> file_sink_ptr;

/// @var g_LogFileSink
/// @brief sink pointer to global log file sink
/// @notes Currently no need for this to be global. Kept for continuity.
file_sink_ptr g_LogFileSink;

/**
 *
 * Global log + channels
 *
 */

/// @typedef core_ptr
/// @brief Boost.Log core pointer
typedef boost::log::core_ptr core_ptr;

/// @var g_Log
/// @brief Shared pointer to global log
static std::shared_ptr<Log> g_Log = nullptr;

/// @typedef log_t
/// @brief Log level/severity channel
typedef boost::log::sources::severity_channel_logger_mt<LogLevel, std::string> log_t;

/**
 *
 * LogStream implementation and definitions
 *
 */

/// @class LogStreamImpl
class LogStreamImpl : public std::streambuf {
 public:
  LogStreamImpl(
      std::mutex& mtx,
      log_t& log,
      LogLevel level)
      : m_Str(std::make_unique<std::stringbuf>()),
        m_Access(mtx),
        m_Log(log),
        m_Level(level),
        m_Enabled(true) {}

  ~LogStreamImpl() {}

  /// @note Not thread safe
  void Flush() {
    BOOST_LOG_SEV(m_Log, m_Level) << m_Str.get();
    m_Str = std::make_unique<std::stringbuf>();
    g_LogOutStreamSink->flush();
  }

  void WaitForReady() {
    {
      std::lock_guard<std::mutex> lock(m_Access);
    }
  }

  std::streambuf::int_type overflow(
      int_type ch) {
    return std::streambuf::overflow(ch);
  }

 protected:
  int sync() {
    int ret = 0;
    ret = m_Str->pubsync();
    Flush();
    m_Access.unlock();
    return ret;
  }

  /// @note Not thread safe
  std::streamsize xsputn(
      const std::streambuf::char_type* s,
      std::streamsize count) {
    return m_Str->sputn(s, count);
  }

 private:
  std::unique_ptr<std::stringbuf> m_Str;
  std::mutex& m_Access;
  log_t& m_Log;
  LogLevel m_Level;
  bool m_Enabled;
};

LogStream::LogStream() {}
LogStream::~LogStream() {}

LogStream::LogStream(
    LogStreamImpl* impl)
    : std::ostream(impl),
      m_LogStreamPimpl(impl) {}

/**
 *
 * Logger implementation and definitions
 *
 */

/// @class LoggerImpl
class LoggerImpl {
 public:
  /// @brief Construct default Logger
  LoggerImpl()
      : LoggerImpl("default", "default") {}

  ~LoggerImpl() {}

  /// @brief Construct logger with a name that belongs in 1 log channel
  LoggerImpl(
      const std::string& name,
      const std::string& channel)
      : m_Log(boost::log::keywords::channel = channel),
        m_Info(new LogStreamImpl(m_InfoMtx, m_Log, eLogInfo)),
        m_Warn(new LogStreamImpl(m_WarnMtx, m_Log, eLogWarn)),
        m_Error(new LogStreamImpl(m_ErrorMtx, m_Log, eLogError)),
        m_Debug(new LogStreamImpl(m_DebugMtx, m_Log, eLogDebug)) {
    m_Log.add_attribute(
        "LogName",
        boost::log::attributes::constant<std::string>(name));
  }

  LogStream& Error() {
    return GetLogStream(m_Error, m_ErrorMtx);
  }

  LogStream& Warn() {
    return GetLogStream(m_Warn, m_WarnMtx);
  }

  LogStream& Info() {
    return GetLogStream(m_Info, m_InfoMtx);
  }

  LogStream& Debug() {
    return GetLogStream(m_Debug, m_DebugMtx);
  }

 private:
  /// @brief Lock mutex and return log stream
  /// @return Reference to LogStream
  LogStream& GetLogStream(
      LogStream& stream,
      std::mutex& mtx) {
    mtx.lock();
    return stream;
  }

 private:
  log_t m_Log;
  LogStream m_Info, m_Warn, m_Error, m_Debug;
  std::mutex m_InfoMtx, m_WarnMtx, m_ErrorMtx, m_DebugMtx;
};

Logger::Logger() {}
Logger::~Logger() {}

Logger::Logger(
    LoggerImpl* impl)
    : m_LoggerPimpl(impl) {}

LogStream& Logger::Error() {
  return m_LoggerPimpl->Error();
}

LogStream& Logger::Warn() {
  return m_LoggerPimpl->Warn();
}

LogStream& Logger::Info() {
  return m_LoggerPimpl->Info();
}

LogStream& Logger::Debug() {
  return m_LoggerPimpl->Debug();
}

/**
 *
 * Log implementation and definitions
 *
 */

/// @class LogImpl
class LogImpl {
 public:
  LogImpl() {}
  ~LogImpl() {}

  LogImpl(
      LogLevel min_level,
      std::ostream* out_stream,
      const std::string& log_file_name)
      : m_LogLevel(min_level),
        m_OutStream(out_stream),
        m_FileName(log_file_name) {
    // Implement core
    m_Core = boost::log::core::get();
    if (m_Core) {
      m_Core->add_global_attribute("Timestamp", boost::log::attributes::local_clock());
      // Add/remove ostream sink
      if (GetOptionLogToConsole())
        m_Core->add_sink(GetOutStreamSink());
      if (!GetOptionLogToConsole())
        m_Core->remove_sink(GetOutStreamSink());
      // Add/remove file sink
      if (GetOptionLogToFile())
        m_Core->add_sink(GetFileSink());
      if (!GetOptionLogToFile())
        m_Core->remove_sink(GetFileSink());
    }
  }

 private:
  /// @brief Initializes ostream backend and sink
  /// @return Initialized and configured global ostream sink
  ostream_sink_ptr GetOutStreamSink() {
    m_OutStreamBackend = boost::make_shared<ostream_backend_t>();
    m_OutStreamBackend->add_stream(boost::shared_ptr<std::ostream>(m_OutStream, boost::null_deleter()));
    g_LogOutStreamSink = boost::shared_ptr<ostream_sink_t>(new ostream_sink_t(m_OutStreamBackend));
    g_LogOutStreamSink->set_filter(boost::log::expressions::attr<LogLevel>("Severity") >= m_LogLevel);
    g_LogOutStreamSink->set_formatter(&LogImpl::Format);
    return g_LogOutStreamSink;
  }

  /// @brief Initializes file backend and sink
  /// @return Initialized and configured global file sink
  /// @notes We use file_backend_sink because simply add_stream'ing a file to
  ///   the ostream backend will not provide needed keywords (AFAICT)
  file_sink_ptr GetFileSink() {
    m_FileBackend = boost::make_shared<file_backend_t>(
          boost::log::keywords::file_name = m_FileName,
          boost::log::keywords::rotation_size = 10 * 1024 * 1024);  // 10 MiB
    g_LogFileSink = boost::shared_ptr<file_sink_t>(new file_sink_t(m_FileBackend));
    g_LogFileSink->set_filter(boost::log::expressions::attr<LogLevel>("Severity") >= m_LogLevel);
    g_LogFileSink->set_formatter(&LogImpl::Format);
    return g_LogFileSink;
  }

  static void Format(
      boost::log::record_view const& rec,
      boost::log::formatting_ostream &stream) {
    static std::locale loc(
        std::clog.getloc(),
        new boost::posix_time::time_facet("%Y:%m:%d|%T.%f"));
    std::stringstream ss;
    ss.imbue(loc);
    ss << boost::log::extract<boost::posix_time::ptime>("Timestamp", rec);
    stream << ss.str();
    // TODO(unassigned):
    // When these become useful, uncomment and tweak
    //stream << "|" << boost::log::extract<std::string>("Channel", rec) << ":";
    //stream << boost::log::extract<std::string>("LogName", rec);
    stream << "|" << boost::log::extract<LogLevel>("Severity", rec) << "   ";
    stream << rec[boost::log::expressions::smessage];
  }

 private:
  LogLevel m_LogLevel;
  std::ostream* m_OutStream;
  std::string m_FileName;
  core_ptr m_Core;
  ostream_backend_ptr m_OutStreamBackend;
  file_backend_ptr m_FileBackend;
};

Log::Log() {}
Log::~Log() {}

Log::Log(
    LogLevel min_level,
    std::ostream* out_stream,
    const std::string& log_file_name) {
  m_LogPimpl = std::make_shared<LogImpl>(min_level, out_stream, log_file_name);
  m_DefaultLogger = std::make_shared<Logger>(new LoggerImpl);
}

std::shared_ptr<Log> Log::GetGlobalLogEngine() {
  // TODO(unassigned): Total hack to ensure that log config log options
  // are loaded first! If not, we won't be able to use config log options
  // because this ctor is initialized upon the first call to LogPrint which,
  // in turn, precedes any config file + cli opt processing.
  // This approach + logging design + library design all need to be rethought.
  // See #96, #98, and #223.
  auto log_file_name = GetOptionLogFileName();
  if (log_file_name.empty())
    return nullptr;
  // Make default logger if we don't have a logger
  if (g_Log == nullptr)
    g_Log = std::make_shared<Log>(eLogDebug, &std::clog, log_file_name);
  return g_Log;
}

std::shared_ptr<Logger> Log::GetDefaultLogger() {
  // TODO(unassigned): see above
  // User disabled all logging
  if (!GetOptionLogToConsole() && !GetOptionLogToFile())
    return nullptr;
  return m_DefaultLogger;
}

std::ostream& operator<<(
    std::ostream& out_stream,
    LogLevel log_level) {
  static std::array<const char*, 4> levels {
    "DBG",  // debug
    "NFO",  // info
    "WRN",  // warn
    "ERR"   // error
  };
  if (static_cast<std::size_t>(log_level) < levels.size()) {
    out_stream << levels.at(log_level);
  } else {
    out_stream << "Invalid log level: " << static_cast<int>(log_level);
  }
  return out_stream;
}

}  // namespace log
}  // namespace util
}  // namespace i2p
