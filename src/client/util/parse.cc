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
 *                                                                                            //
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project          //
 */

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/lexical_cast.hpp>

#include <string>
#include <vector>

#include "client/util/parse.h"

#include "core/util/log.h"

namespace kovri {
namespace client {

// TODO(unassigned): boost::split refactor? If so, then pass custom delimiter and
// rename function. If there are not many use-cases, simply use directly within
// implementation and remove this unit-test.
const std::vector<std::string> ParseCSV(
    const std::string& record) {
  std::vector<std::string> parsed;
  if (!record.empty()) {
    std::size_t pos = 0, comma;
    do {
      comma = record.find(',', pos);
      auto value =
        record.substr(
            pos,
            comma != std::string::npos ? comma - pos : std::string::npos);
      parsed.push_back(value);
      pos = comma + 1;
    } while (comma != std::string::npos);
  }
  return parsed;
}

// TODO(anonimal): see TODO in declaration
void ParseClientDestination(
    TunnelAttributes* tunnel) {
  // Get all destination(s)
  auto parsed = ParseCSV(tunnel->dest);
  // Pick random destination (if applicable)
  if (parsed.size() > 1) {
    // Shuffle to ensure all destinations are accessible
    // TODO(anonimal): review RandInRange() so we don't need to shuffle
    kovri::core::Shuffle(parsed.begin(), parsed.end());
    tunnel->dest =
      parsed.at(kovri::core::RandInRange32(0, parsed.size() - 1));
  }
  LOG(debug) << "Client: parsing destination " << tunnel->dest;
  // If dest has port appended to it, replace previously set dest port
  std::vector<std::string> dest;
  boost::split(dest, tunnel->dest, boost::is_any_of(":"));
  // Return if parsed destination doesn't have port field
  if (dest.size() <= 1)
    return;
  try {
    // Address book is designed (should be) to handle legitimacy of destination
    // TODO(unassigned): a catch-all utility function to verify would be useful
    tunnel->dest = dest.at(0);
    tunnel->dest_port = boost::lexical_cast<std::uint16_t>(dest.at(1));
    LOG(debug)
      << "Client: using " << tunnel->dest << " port " << tunnel->dest_port;
  } catch (const boost::bad_lexical_cast& ex) {
    throw std::runtime_error(
        "Client: destination port " + std::string(ex.what()));
  } catch (const std::exception& ex) {
    throw std::runtime_error(
        "Client: exception in " + std::string(__func__)
        + ": " + std::string(ex.what()));
  } catch (...) {
    throw std::runtime_error(
        "Client: unknown exception in " + std::string(__func__));
  }
}

}  // namespace client
}  // namespace kovri
