/**
 * Copyright (c) 2015-2016, The Kovri I2P Router Project
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
 */

#ifndef SRC_CORE_UTIL_LOG_H_
#define SRC_CORE_UTIL_LOG_H_

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

// TODO(unassigned): remove these when removing deprecated logger
#define eLogDebug i2p::util::log::eLogLevelDebug
#define eLogInfo i2p::util::log::eLogLevelInfo
#define eLogWarning i2p::util::log::eLogLevelWarning
#define eLogError i2p::util::log::eLogLevelError

namespace i2p {
namespace util {
namespace log {

enum LogLevel {
  eLogLevelDebug,
  eLogLevelInfo,
  eLogLevelWarning,
  eLogLevelError
};

// core
typedef boost::log::core_ptr core_ptr;
// backend
typedef boost::log::sinks::text_ostream_backend backend_t;
typedef boost::shared_ptr<backend_t> backend_ptr;
// sink
typedef boost::log::sinks::asynchronous_sink<backend_t> sink_t;
typedef boost::shared_ptr<sink_t> sink_ptr;
// level
typedef boost::log::sources::severity_channel_logger_mt<LogLevel, std::string> log_t;

//
// LogStreamImpl <- LogStream
//
class LogStreamImpl : public std::streambuf {
 public:
  LogStreamImpl(
      std::mutex& access,
      log_t& l,
      LogLevel levelno);
  ~LogStreamImpl();

  void MetaImpl(
      const std::string& key,
      std::string value);

  bool IsEnabled() {
    return m_Enable;
  }

  void Disable() {
    m_Enable = false;
  }

  void Enable() {
    m_Enable = true;
  }

  std::streambuf::int_type overflow(
      std::streambuf::int_type ch);

  void WaitForReady();

 protected:
  int sync();
  std::streamsize xsputn(
      const std::streambuf::char_type* s,
      std::streamsize count);

 private:
  void Flush();
  std::stringbuf* m_Str;
  std::mutex& m_Access;
  log_t& m_Log;
  LogLevel m_Level;
  bool m_Enable;
};

class LogStream : public std::ostream {
 public:
  explicit LogStream(
      LogStreamImpl* impl);
  ~LogStream();

  // TODO(unassigned): implement (currently unfinished)
  // // attach metadata to the current logger's next entries until flushed
  // LogStream& Meta(
  //    const std::string& key,
  //    std::string value);

  // flush this log stream
  LogStream& Flush();

  // check if this stream is enabled
  // return true if it is
  bool IsEnabled();

  // disable logging on this stream
  void Disable();

  // enable logging on this stream
  void Enable();

 private:
  LogStreamImpl* m_Impl;
};

// // TODO(unassigned): implement (currently unfinished)
// class BoostEventStream : public EventStream {
//  public:
//   virtual EventStream& Flush() const {}
//   virtual EventStream& operator <<(
//       const std::vector<std::string>& strs) const {}
// };

//
// LoggerImpl <- Logger
//
class LoggerImpl {
 public:
  // Construct default Logger
  LoggerImpl();
  // Construct logger with a name that belongs in 1 log channel
  LoggerImpl(
      const std::string& name,
      const std::string& channel);

  LogStream& Debug();
  LogStream& Info();
  LogStream& Warning();
  LogStream& Error();

  // TODO(unassigned): implement (currently unfinished)
  // EventStream& UI() {
  //  return m_Events;
  //}

  log_t log;

 private:
  LogStream& GetLogger(
      LogStream& log,
      std::mutex& mtx);

  std::mutex m_DebugMtx,
             m_InfoMtx,
             m_WarnMtx,
             m_ErrorMtx;

  LogStream m_Debug,
            m_Info,
            m_Warn,
            m_Error;

  // TODO(unassigned): implement (currently unfinished)
  // BoostEventStream m_Events;
};

class Logger {
 public:
  Logger(
      LoggerImpl* impl);
  ~Logger();

  LogStream& Error();
  LogStream& Warning();
  LogStream& Info();
  LogStream& Debug();

  // TODO(unassigned): implement (currently unfinished)
  // get EventStream to send events to UI
  // EventStream& UI();

  // flush pending log events
  void Flush();

 private:
  LoggerImpl* m_Impl;
};

//
// LogImpl <- Log
//
class LogImpl {
 public:
  LogImpl(
      LogLevel minLevel,
      std::ostream* out);
  LogImpl()
      : LogImpl(
          eLogDebug,
          &std::clog) {}

  void Flush();

  void Stop();

  bool IsSilent();

 private:
  bool m_Silent;
  backend_ptr m_LogBackend;
  core_ptr m_LogCore;
  static void Format(
      boost::log::record_view const& rec,
      boost::log::formatting_ostream &s);
};

/**
 * // TODO(unassigned): implement (currently unfinished)
 * // Stream for sending events to live UI
 * class EventStream {
 *  public:
 *   // flush events
 *   virtual EventStream& Flush() const = 0;
 *   // operator overload for <<
 *   // queue an event
 *   virtual EventStream& operator <<(
 *       const std::vector<std::string> & strs) const = 0;
 * };
 */

class Log {
 public:
  Log(
      LogLevel minLev,
      std::ostream* out);
  Log()
      : Log(
          eLogLevelWarning,
          &std::clog) {}

  // Get global log engine
  static std::shared_ptr<Log> Get();

  // Get default logger
  std::shared_ptr<Logger> Default();

  // Create a logger's given name
  std::unique_ptr<Logger> New(
      const std::string& name,
      const std::string& channel);

  // turn off logging forever
  void Stop();

  // is logging silent right now?
  bool Silent();

 private:
  std::shared_ptr<LogImpl> m_LogImpl;
  std::shared_ptr<Logger> m_DefaultLogger;
};

}  // namespace log
}  // namespace util
}  // namespace i2p

//
// Deprecated Logger
//

#include <sstream>

void DeprecatedStartLog(
    const std::string& fullFilePath);

void DeprecatedStartLog(
    std::ostream* s);

void DeprecatedStopLog();

template<typename TValue>
void DeprecatedLog(
    std::ostream& s,
    TValue arg) {
  s << arg;
}

template<typename TValue, typename... TArgs>
void DeprecatedLog(
    std::ostream& s,
    TValue arg,
    TArgs... args) {
  DeprecatedLog(s, arg);
  DeprecatedLog(s, args...);
}

template<typename... TArgs>
void DeprecatedLogPrint(
    i2p::util::log::LogLevel level,
    TArgs... args) {
  auto l = i2p::util::log::Log::Get();
  if (l == nullptr) {
    // fallback logging to std::clog
    std::clog << "!!! ";
    DeprecatedLog(std::clog, args...);
    std::clog << std::endl;
  } else {
    auto log = l->Default();
    if (level == eLogDebug) {
      auto& s = log->Debug();
      DeprecatedLog(s, args...);
      s << std::flush;
    } else if (level == eLogInfo) {
      auto& s = log->Info();
      DeprecatedLog(s, args...);
      s << std::flush;
    } else if (level == eLogWarning) {
      auto& s = log->Warning();
      DeprecatedLog(s, args...);
      s << std::flush;
    } else  {
      auto& s = log->Error();
      DeprecatedLog(s, args...);
      s << std::flush;
    }
  }
}

template<typename... TArgs>
void DeprecatedLogPrint(
    TArgs... args) {
  DeprecatedLogPrint(eLogInfo, args...);
}

#define StopLog DeprecatedStopLog
#define StartLog DeprecatedStartLog
#define LogPrint DeprecatedLogPrint

#endif  // SRC_CORE_UTIL_LOG_H_
