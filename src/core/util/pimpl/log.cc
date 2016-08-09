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

#include <boost/version.hpp>

#if BOOST_VERSION >= 105600
#include <boost/core/null_deleter.hpp>
#else
// defines null_deleter here if we don't have the right boost version
#include <boost/config.hpp>
namespace boost {
struct null_deleter {
  typedef void result_type;
  template <typename T> void operator() (T*) const {}
};
}
#endif

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <boost/log/attributes.hpp>
#include <boost/log/core.hpp>
#include <boost/log/core/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks.hpp>
#include <boost/log/sinks/async_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/sources/channel_feature.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/sources/severity_feature.hpp>

#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace i2p {
namespace util {
namespace log {

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

/// @typedef core_ptr
/// @brief Boost.Log core pointer
typedef boost::log::core_ptr core_ptr;

/// @typedef backend_t
/// @brief Boost.Log text ostream backend sink
typedef boost::log::sinks::text_ostream_backend backend_t;

/// @typedef backend_ptr
/// @brief Shared pointer to backend sink
typedef boost::shared_ptr<backend_t> backend_ptr;

/// @typedef sink_t
/// @brief Boost.Log asynchronous sink
typedef boost::log::sinks::asynchronous_sink<backend_t> sink_t;

/// @typedef sink_ptr
/// @brief Shared pointer to sink
typedef boost::shared_ptr<sink_t> sink_ptr;

/// @var g_LogSink
/// @brief sink pointer to global log sink
sink_ptr g_LogSink;

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

  void Enable() {
    m_Enabled = true;
  }

  void Disable() {
    m_Enabled = false;
  }

  /// @note Not thread safe
  void Flush() {
    if (g_Log->Silent()) {
      // Don't log if we are silent
      return;
    }
    BOOST_LOG_SEV(m_Log, m_Level) << m_Str.get();
    m_Str = std::make_unique<std::stringbuf>();
    g_LogSink->flush();
  }

  bool IsEnabled() {
    return m_Enabled;
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

void LogStream::Enable() {
  m_LogStreamPimpl->Enable();
}

void LogStream::Disable() {
  m_LogStreamPimpl->Disable();
}

LogStream& LogStream::Flush() {
  m_LogStreamPimpl->Flush();
  return *this;
}

bool LogStream::IsEnabled() {
  return m_LogStreamPimpl->IsEnabled();
}

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

  void Flush() {
    g_LogSink->flush();
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

void Logger::Flush() {
  m_LoggerPimpl->Flush();
}

/**
 *
 * Log implementation and definitions
 *
 */

/// @class LogImpl
class LogImpl {
 public:
  LogImpl() : LogImpl(eLogDebug, &std::clog) {}

  ~LogImpl() {}

  LogImpl(
      LogLevel min_level,
      std::ostream* out_stream) {
    // Running
    m_Silent = false;
    // Backend
    m_LogBackend = boost::make_shared<backend_t>();
    m_LogBackend->add_stream(boost::shared_ptr<std::ostream>(out_stream, boost::null_deleter()));
    // Sink
    g_LogSink = boost::shared_ptr<sink_t>(new sink_t(m_LogBackend));
    g_LogSink->set_filter(boost::log::expressions::attr<LogLevel>("Severity") >= min_level);
    g_LogSink->set_formatter(&LogImpl::Format);
    // Core
    m_LogCore = boost::log::core::get();
    m_LogCore->add_sink(g_LogSink);
    m_LogCore->add_global_attribute("Timestamp", boost::log::attributes::local_clock());
  }

  void Flush() {
    g_LogSink->flush();
  }

  void Stop() {
    m_Silent = true;
  }

  bool IsSilent() {
    return m_Silent;
  }

 private:
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
  backend_ptr m_LogBackend;
  core_ptr m_LogCore;
  bool m_Silent;
};

Log::Log() : Log(eLogDebug, &std::clog) {}
Log::~Log() {}

Log::Log(
    LogLevel min_level,
    std::ostream* out_stream) {
  m_LogPimpl = std::make_shared<LogImpl>(min_level, out_stream);
  m_DefaultLogger = std::make_shared<Logger>(new LoggerImpl);
}

void Log::Stop() {
  m_LogPimpl->Stop();
}

bool Log::Silent() {
  return m_LogPimpl->IsSilent();
}

std::shared_ptr<Log> Log::Get() {
    // Make default logger if we don't have a logger
  if (g_Log == nullptr)
    g_Log = std::make_shared<Log>(eLogDebug, &std::clog);
  return g_Log;
}

std::shared_ptr<Logger> Log::Default() {
  return m_DefaultLogger;
}

// TODO(unassigned):
// Uncomment when this becomes useful
//std::unique_ptr<Logger> Log::New(
    //const std::string& name,
    //const std::string& channel) {
  //return std::unique_ptr<Logger>(new Logger(new LoggerImpl(name, channel)));
//}

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

/**
 *
 * Deprecated Logger
 *
 */

void DeprecatedStartLog(
    const std::string& full_file_path) {
  std::cerr << "Not opening log file: " << full_file_path << std::endl;
}

void DeprecatedStartLog(
    std::ostream* stream) {
  *stream << "Deprecated Logging not implemented" << std::endl;
}

void DeprecatedStopLog() {}
