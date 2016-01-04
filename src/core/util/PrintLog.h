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

#ifndef SRC_CORE_UTIL_PRINTLOG_H_
#define SRC_CORE_UTIL_PRINTLOG_H_

#include "Log.h"

#include <mutex>
#include <string>

/* TODO(unassigned): implement */

namespace kovri {
namespace log {

class LogStreamImpl : public std::streambuf {
 public:
  LogStreamImpl(
      std::ostream& out,
      std::mutex& mtx)
      : m_Out(out),
        m_Access(mtx),
        m_Enable(true) {}
  ~LogStreamImpl() {}

  void MetaImpl(
      const std::string& key,
      std::string& value) {}

  bool IsEnabled() {
    return m_Enable;
  }

  void Disable() {
    m_Enable = false;
  }

  void Enable() {
    m_Enable = true;
  }

  int_type overflow(int_type ch);

 protected:
  using char_type = typename std::streambuf::char_type;

  int sync();

  std::streamsize xsputn(
      const char_type* s,
      std::streamsize count);

 private:
  std::stringbuf m_Str;
  std::ostream& m_Out;
  std::mutex& m_Access;
  bool m_Enable;
};

class LoggerImpl {
 public:
  LoggerImpl(
      LogLevel minlev,
      const std::string& name,
      std::ostream & out)
      : m_MinLevel(minlev),
        m_LogName(name),
        m_Out(out),
        m_LogStream(
            new LogStreamImpl(
              m_Out,
              m_LogMtx)) {}

  LogStream& GetLogStream(
      const std::string & name);

  void SetMinLevel(
      LogLevel lev) {
    m_MinLevel = lev;
  }

 private:
  LogLevel m_MinLevel;
  std::string m_LogName;
  std::mutex m_LogMtx;
  std::ostream& m_Out;
  LogStream m_LogStream;
};

class LogImpl {
 public:
  LogImpl(
      LogLevel minLevel,
      std::ostream& out);
  LogImpl()
      : LogImpl(
          eLogDebug,
          std::clog) {}

  std::ostream& Out() {
    return m_Out;
  }

  LogLevel CurrentLevel() {
    return m_LogLevel;
  }

 private:
  LogLevel m_LogLevel;
  std::ostream& m_Out;
};

}  // namespace log
}  // namespace kovri

#endif  // SRC_CORE_UTIL_PRINTLOG_H_
