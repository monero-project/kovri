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

namespace kovri {
namespace tunnel {

struct TunnelHopConfig {
  explicit TunnelHopConfig(
      std::shared_ptr<const kovri::data::RouterInfo> r);

  void SetNextRouter(
      std::shared_ptr<const kovri::data::RouterInfo> r);

  void SetReplyHop(
      const TunnelHopConfig* reply_first_hop);

  void SetNext(
      TunnelHopConfig* n);

  void SetPrev(
      TunnelHopConfig* p);

  void CreateBuildRequestRecord(
      uint8_t* record,
      uint32_t reply_msg_ID) const;

  std::shared_ptr<const kovri::data::RouterInfo> router,
                                               next_router;

  uint32_t tunnel_ID,
           next_tunnel_ID;

  uint8_t layer_key[32],
          iv_key[32],
          reply_key[32],
          reply_IV[16],
          rand_pad[29];

  bool is_gateway,
       is_endpoint;

  TunnelHopConfig *next,
                  *prev;

  kovri::crypto::TunnelDecryption decryption;
  int record_index;  // record # in tunnel build message
};

class TunnelConfig : public std::enable_shared_from_this<TunnelConfig> {
 public:
  TunnelConfig(
      std::vector<std::shared_ptr<const kovri::data::RouterInfo> > peers,
      std::shared_ptr<const TunnelConfig> reply_tunnel_config = nullptr);
  ~TunnelConfig();

  TunnelHopConfig* GetFirstHop() const;

  TunnelHopConfig* GetLastHop() const;

  int GetNumHops() const;

  bool IsInbound() const;

  std::vector<std::shared_ptr<const kovri::data::RouterInfo> > GetPeers() const;

  void Print(
      std::stringstream& s) const;

  std::shared_ptr<TunnelConfig> Invert() const;

  std::shared_ptr<TunnelConfig> Clone(
      std::shared_ptr<const TunnelConfig> reply_tunnel_config = nullptr) const;

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
}  // namespace kovri

#endif  // SRC_CORE_TUNNEL_TUNNEL_CONFIG_H_
