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

#ifndef SRC_CORE_TUNNEL_TUNNEL_ENDPOINT_H_
#define SRC_CORE_TUNNEL_TUNNEL_ENDPOINT_H_

#include <inttypes.h>

#include <map>
#include <string>

#include "i2np_protocol.h"
#include "tunnel_base.h"

namespace i2p {
namespace tunnel {

class TunnelEndpoint {
  struct TunnelMessageBlockEx : public TunnelMessageBlock {
    uint8_t nextFragmentNum;
  };

  struct Fragment {
    uint8_t fragmentNum;
    bool isLastFragment;
    std::shared_ptr<I2NPMessage> data;
  };

 public:
    TunnelEndpoint(
        bool isInbound)
        : m_IsInbound(isInbound),
          m_NumReceivedBytes(0) {}
    ~TunnelEndpoint();

    size_t GetNumReceivedBytes() const {
      return m_NumReceivedBytes;
    }

    void HandleDecryptedTunnelDataMsg(
        std::shared_ptr<I2NPMessage> msg);

 private:
    void HandleFollowOnFragment(
        uint32_t msgID,
        bool isLastFragment,
        const TunnelMessageBlockEx& m);

    void HandleNextMessage(
        const TunnelMessageBlock& msg);

    void AddOutOfSequenceFragment(
        uint32_t msgID,
        uint8_t fragmentNum,
        bool isLastFragment,
        std::shared_ptr<I2NPMessage> data);

    void HandleOutOfSequenceFragment(
        uint32_t msgID,
        TunnelMessageBlockEx& msg);

 private:
    std::map<uint32_t, TunnelMessageBlockEx> m_IncompleteMessages;
    std::map<uint32_t, Fragment> m_OutOfSequenceFragments;
    bool m_IsInbound;
    size_t m_NumReceivedBytes;
};

}  // namespace tunnel
}  // namespace i2p

#endif  // SRC_CORE_TUNNEL_TUNNEL_ENDPOINT_H_
