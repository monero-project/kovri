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

#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace kovri {
namespace log {

enum LogLevel {
  eLogLevelDebug,
  eLogLevelInfo,
  eLogLevelWarning,
  eLogLevelError
};

// private implemenation of LogStream
class LogStreamImpl;

// Generic Log stream
class LogStream : public std::ostream {
 public:
  explicit LogStream(
      LogStreamImpl* impl);
  ~LogStream();

  /**
   * TODO(unassigned): implement (currently unfinished)
   * // attach metadata to the current logger's next entries until flushed
   * LogStream& Meta(
   *    const std::string& key,
   *    std::string value);
  */

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

// private implementation of Logger
class LoggerImpl;

class Logger {
 public:
  Logger(
      LoggerImpl* impl);
  ~Logger();

  // get error level log stream
  LogStream& Error();

  // get warning level log stream
  LogStream& Warning();

  // get info level log stream
  LogStream& Info();

  // get debug level log stream
  LogStream& Debug();

  // TODO(unassigned): implement (currently unfinished)
  // get EventStream to send events to UI
  //EventStream& UI();

  // flush pending log events
  void Flush();

 private:
  LoggerImpl* m_Impl;
};

class LogImpl;

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

  // get default logger
  std::shared_ptr<Logger> Default();

  // create a logger given name
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
}  // namespace kovri

#include "util/OldLog.h"

typedef std::unique_ptr<kovri::log::Logger> Logger_t;

#endif  // SRC_CORE_UTIL_LOG_H_
