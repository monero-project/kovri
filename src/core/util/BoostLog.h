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

#ifndef SRC_CORE_UTIL_BOOSTLOG_H_
#define SRC_CORE_UTIL_BOOSTLOG_H_

#include <boost/log/core/core.hpp>
#include <boost/log/sinks/async_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "Log.h"

namespace kovri {
namespace log {

// core
typedef boost::log::core_ptr core_ptr;
// backend
typedef boost::log::sinks::text_ostream_backend backend_t;
typedef boost::shared_ptr<backend_t> backend_ptr;
// sink
typedef boost::log::sinks::asynchronous_sink< backend_t > sink_t;
typedef boost::shared_ptr<sink_t> sink_ptr;
// level
typedef boost::log::sources::severity_channel_logger_mt<LogLevel, std::string> log_t;

class LogStreamImpl : public std::streambuf {
 public:
  using int_type = typename std::streambuf::int_type;

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

  int_type overflow(
      int_type ch);

  void WaitForReady();

 protected:
  using char_type = typename std::streambuf::char_type;
  int sync();
  std::streamsize xsputn(
      const char_type* s,
      std::streamsize count);

 private:
  void Flush();
  std::stringbuf* m_Str;
  std::mutex& m_Access;
  log_t& m_Log;
  LogLevel m_Level;
  bool m_Enable;
};

/**
 * // TODO(unassigned): implement (currently unfinished)
 * class BoostEventStream : public EventStream {
 *  public:
 *   virtual EventStream& Flush() const {}
 *   virtual EventStream& operator <<(
 *       const std::vector<std::string>& strs) const {}
 * };
 */

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
  //EventStream& UI() {
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
  //BoostEventStream m_Events;
};

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

}  // namespace log
}  // namespace kovri

#endif  // SRC_CORE_UTIL_BOOSTLOG_H_
