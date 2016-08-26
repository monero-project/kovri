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

#ifndef SRC_CORE_TUNNEL_TUNNEL_GATEWAY_H_
#define SRC_CORE_TUNNEL_TUNNEL_GATEWAY_H_

#include <inttypes.h>

#include <memory>
#include <vector>

#include "i2np_protocol.h"
#include "tunnel_base.h"

namespace i2p {
namespace tunnel {

class TunnelGatewayBuffer {
 public:
  TunnelGatewayBuffer(
      uint32_t tunnelID);
  ~TunnelGatewayBuffer();

  void PutI2NPMsg(
      const TunnelMessageBlock& block);

  const std::vector<std::shared_ptr<I2NPMessage> >& GetTunnelDataMsgs() const {
    return m_TunnelDataMsgs;
  }

  void ClearTunnelDataMsgs();

  void CompleteCurrentTunnelDataMessage();

 private:
  void CreateCurrentTunnelDataMessage();

 private:
  uint32_t m_TunnelID;
  std::vector<std::shared_ptr<I2NPMessage> > m_TunnelDataMsgs;
  std::shared_ptr<I2NPMessage> m_CurrentTunnelDataMsg;
  size_t m_RemainingSize;
  uint8_t m_NonZeroRandomBuffer[TUNNEL_DATA_MAX_PAYLOAD_SIZE];
};

class TunnelGateway {
 public:
  TunnelGateway(
      TunnelBase* tunnel)
      : m_Tunnel(tunnel),
        m_Buffer(tunnel->GetNextTunnelID()),
        m_NumSentBytes(0) {}

  void SendTunnelDataMsg(
      const TunnelMessageBlock& block);

  void PutTunnelDataMsg(
      const TunnelMessageBlock& block);

  void SendBuffer();

  size_t GetNumSentBytes() const {
    return m_NumSentBytes;
  }

 private:
  TunnelBase* m_Tunnel;
  TunnelGatewayBuffer m_Buffer;
  size_t m_NumSentBytes;
};

}  // namespace tunnel
}  // namespace i2p

#endif  // SRC_CORE_TUNNEL_TUNNEL_GATEWAY_H_
