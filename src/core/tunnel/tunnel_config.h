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

#ifndef SRC_CORE_TUNNEL_TUNNEL_CONFIG_H_
#define SRC_CORE_TUNNEL_TUNNEL_CONFIG_H_

#include <memory>
#include <cstdint>
#include <vector>
#include <sstream>

#include "router_info.h"
#include "crypto/tunnel.h"

namespace i2p {
namespace tunnel {

struct TunnelHopConfig {
  explicit TunnelHopConfig(
      std::shared_ptr<const i2p::data::RouterInfo> r);

  void SetNextRouter(
      std::shared_ptr<const i2p::data::RouterInfo> r);

  void SetReplyHop(
      const TunnelHopConfig* replyFirstHop);

  void SetNext(
      TunnelHopConfig* n);

  void SetPrev(
      TunnelHopConfig* p);

  void CreateBuildRequestRecord(
      uint8_t* record,
      uint32_t replyMsgID) const;

  std::shared_ptr<const i2p::data::RouterInfo> router,
                                               nextRouter;

  uint32_t tunnelID,
           nextTunnelID;

  uint8_t layerKey[32],
          ivKey[32],
          replyKey[32],
          replyIV[16],
          randPad[29];

  bool isGateway,
       isEndpoint;

  TunnelHopConfig *next,
                  *prev;

  i2p::crypto::TunnelDecryption decryption;
  int recordIndex;  // record # in tunnel build message
};

class TunnelConfig : public std::enable_shared_from_this<TunnelConfig> {
 public:
  TunnelConfig(
      std::vector<std::shared_ptr<const i2p::data::RouterInfo> > peers,
      std::shared_ptr<const TunnelConfig> replyTunnelConfig = nullptr);
  ~TunnelConfig();

  TunnelHopConfig* GetFirstHop() const;

  TunnelHopConfig* GetLastHop() const;

  int GetNumHops() const;

  bool IsInbound() const;

  std::vector<std::shared_ptr<const i2p::data::RouterInfo> > GetPeers() const;

  void Print(
      std::stringstream& s) const;

  std::shared_ptr<TunnelConfig> Invert() const;

  std::shared_ptr<TunnelConfig> Clone(
      std::shared_ptr<const TunnelConfig> replyTunnelConfig = nullptr) const;

 private:
  // this constructor can't be called from outside
  TunnelConfig()
      : m_FirstHop(nullptr),
        m_LastHop(nullptr) {}

 private:
  TunnelHopConfig *m_FirstHop,
                  *m_LastHop;
};

}  // namespace tunnel
}  // namespace i2p

#endif  // SRC_CORE_TUNNEL_TUNNEL_CONFIG_H_
