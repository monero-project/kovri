/**                                                                                           //
 * Copyright (c) 2013-2017, The Kovri I2P Router Project                                      //
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
 */

#include "core/util/log.h"

#include <boost/core/null_deleter.hpp>
#include <boost/log/attributes.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/expressions/formatters/date_time.hpp>
#include <boost/log/sinks.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/make_shared.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/shared_ptr.hpp>

#include <memory>
#include "src/core/util/filesystem.h"

// TODO(anonimal):
// Boost.Log uses an "application-wide singleton" (note: our logger/sink setup applies globally from instance configuration)
// As a result, logging will not work when in daemon mode. http://www.boost.org/doc/libs/1_63_0/libs/log/doc/html/log/rationale/fork_support.html
// We've worked around this problem in the past by using some very gross hacking but we may be able to apply a cleaner work-around so we can set this up entirely in the core namespace
// (we could create an (inheritable?) logging class with overloaded stream operator and adjust our logging initialization and macro accordingly, or consider other options)
// Also note that a singleton will effect having multiple logging library options (there's no need to do that though when we have huge flexibility with sinks)

BOOST_LOG_GLOBAL_LOGGER_INIT(g_Logger, boost::log::sources::severity_logger_mt) {
  boost::log::sources::severity_logger_mt<boost::log::trivial::severity_level> logger;
  return logger;
}

namespace kovri
{
namespace core
{
void SetupLogging(const boost::program_options::variables_map& kovri_config)
{
  namespace logging = boost::log;
  namespace expr = boost::log::expressions;
  namespace sinks = boost::log::sinks;
  namespace attrs = boost::log::attributes;
  namespace keywords = boost::log::keywords;
  // Get global logger
  // TODO(unassigned): depends on global logging initialization. See notes in log impl
  auto core = logging::core::get();
  // Add core attributes
  core->add_global_attribute("TimeStamp", attrs::utc_clock());
  core->add_global_attribute("ThreadID", attrs::current_thread_id());
  // Get/Set filter log level
  auto log_level = kovri_config["log-level"].as<std::uint16_t>();
  logging::trivial::severity_level severity;
  switch (log_level)
    {
      case 0:
        severity = logging::trivial::fatal;
        break;
      case 1:
        severity = logging::trivial::error;
        break;
      case 2:
        severity = logging::trivial::warning;
        break;
      case 3:
        severity = logging::trivial::info;
        break;
      case 4:
        severity = logging::trivial::debug;
        break;
      case 5:
        severity = logging::trivial::trace;
        break;
      default:
        throw std::invalid_argument(
            "Configuration: invalid log-level, see documentation");
        break;
    };
  core->set_filter(
      expr::attr<logging::trivial::severity_level>("Severity") >= severity);
  // Create text backend + sink
  typedef sinks::synchronous_sink<sinks::text_ostream_backend>
      text_ostream_sink;
  auto text_sink = boost::make_shared<text_ostream_sink>();
  text_sink->locked_backend()->add_stream(
      boost::shared_ptr<std::ostream>(&std::clog, boost::null_deleter()));
  // Create file backend
  typedef sinks::asynchronous_sink<sinks::text_file_backend> text_file_sink;
  auto file_backend = boost::make_shared<sinks::text_file_backend>(
      keywords::file_name =
          kovri_config["log-file-name"].defaulted()
              ? ((kovri::core::GetLogsPath() / "kovri_%Y-%m-%d.log").string())
              : kovri_config["log-file-name"].as<std::string>(),
      keywords::time_based_rotation =
          sinks::file::rotation_at_time_point(0, 0, 0));  // Rotate at midnight
  // If debug/trace, enable auto flush to (try to) catch records right before segfault
  if (severity <= logging::trivial::
                      debug)  // Our severity levels are processed in reverse
    file_backend->auto_flush();
  // Create file sink
  auto file_sink = boost::shared_ptr<text_file_sink>(
      std::make_unique<text_file_sink>(file_backend));
  // Set sink formatting
  logging::formatter format =
      expr::stream << "["
                   << expr::format_date_time(
                          expr::attr<boost::posix_time::ptime>("TimeStamp"),
                          "%Y.%m.%d %T.%f")
                   << "]"
                   << " [" << expr::attr<attrs::current_thread_id::value_type>(
                                  "ThreadID")
                   << "]"
                   << " [" << logging::trivial::severity << "]"
                   << "  " << expr::smessage;
  text_sink->set_formatter(format);
  file_sink->set_formatter(format);
  // Add sinks
  core->add_sink(text_sink);
  core->add_sink(file_sink);
  // Remove sinks if needed (we must first have added sinks to remove)
  bool log_to_console = kovri_config["log-to-console"].as<bool>();
  bool log_to_file = kovri_config["log-to-file"].as<bool>();
  if (!log_to_console)
    core->remove_sink(text_sink);
  if (!log_to_file)
    core->remove_sink(file_sink);
}

}  // namespace core
}  // namespace kovri
