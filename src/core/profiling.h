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

#ifndef SRC_CORE_PROFILING_H_
#define SRC_CORE_PROFILING_H_

#include <boost/date_time/posix_time/posix_time.hpp>

#include <memory>

#include "identity.h"

namespace i2p {
namespace data {

const char PEER_PROFILES_DIRECTORY[] = "peerProfiles";
const char PEER_PROFILE_PREFIX[] = "profile-";
// sections
const char PEER_PROFILE_SECTION_PARTICIPATION[] = "participation";
const char PEER_PROFILE_SECTION_USAGE[] = "usage";
// params
const char PEER_PROFILE_LAST_UPDATE_TIME[] = "lastupdatetime";
const char PEER_PROFILE_PARTICIPATION_AGREED[] = "agreed";
const char PEER_PROFILE_PARTICIPATION_DECLINED[] = "declined";
const char PEER_PROFILE_PARTICIPATION_NON_REPLIED[] = "nonreplied";
const char PEER_PROFILE_USAGE_TAKEN[] = "taken";
const char PEER_PROFILE_USAGE_REJECTED[] = "rejected";

const int PEER_PROFILE_EXPIRATION_TIMEOUT = 72;  // in hours (3 days)

class RouterProfile {
 public:
  explicit RouterProfile(const IdentHash& identHash);
  RouterProfile& operator=(const RouterProfile&) = default;

  void Save();
  void Load();

  bool IsBad();

  void TunnelBuildResponse(uint8_t ret);
  void TunnelNonReplied();

 private:
  boost::posix_time::ptime GetTime() const;
  void UpdateTime();

  bool IsAlwaysDeclining() const {
    return !m_NumTunnelsAgreed && m_NumTunnelsDeclined >= 5;
  }

  bool IsLowPartcipationRate() const;
  bool IsLowReplyRate() const;

 private:
  IdentHash m_IdentHash;
  boost::posix_time::ptime m_LastUpdateTime;
  // participation
  uint32_t m_NumTunnelsAgreed;
  uint32_t m_NumTunnelsDeclined;
  uint32_t m_NumTunnelsNonReplied;
  // usage
  uint32_t m_NumTimesTaken;
  uint32_t m_NumTimesRejected;
};

std::shared_ptr<RouterProfile> GetRouterProfile(
    const IdentHash& identHash);

void DeleteObsoleteProfiles();

}  // namespace data
}  // namespace i2p

#endif  // SRC_CORE_PROFILING_H_
