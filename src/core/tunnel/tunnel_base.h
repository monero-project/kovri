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

#ifndef SRC_CORE_TUNNEL_TUNNEL_BASE_H_
#define SRC_CORE_TUNNEL_TUNNEL_BASE_H_

#include <inttypes.h>

#include <memory>

#include "i2np_protocol.h"
#include "identity.h"
#include "util/timestamp.h"

namespace i2p {
namespace tunnel {

const size_t TUNNEL_DATA_MSG_SIZE = 1028;
const size_t TUNNEL_DATA_ENCRYPTED_SIZE = 1008;
const size_t TUNNEL_DATA_MAX_PAYLOAD_SIZE = 1003;

enum TunnelDeliveryType {
  e_DeliveryTypeLocal = 0,
  e_DeliveryTypeTunnel = 1,
  e_DeliveryTypeRouter = 2
};

struct TunnelMessageBlock {
  TunnelDeliveryType deliveryType;
  i2p::data::IdentHash hash;
  uint32_t tunnelID;
  std::shared_ptr<I2NPMessage> data;
};

class TunnelBase {
 public:
  TunnelBase()
      : m_CreationTime(i2p::util::GetSecondsSinceEpoch()) {}
      // WARNING!!! GetSecondsSinceEpoch() returns uint64_t
      // TODO(unassigned): ^
  virtual ~TunnelBase() {}

  virtual void HandleTunnelDataMsg(
      std::shared_ptr<const i2p::I2NPMessage> tunnelMsg) = 0;

  virtual void SendTunnelDataMsg(
      std::shared_ptr<i2p::I2NPMessage> msg) = 0;

  virtual void FlushTunnelDataMsgs() {}

  virtual void EncryptTunnelMsg(
      std::shared_ptr<const I2NPMessage> in,
      std::shared_ptr<I2NPMessage> out) = 0;

  virtual uint32_t GetNextTunnelID() const = 0;

  virtual const i2p::data::IdentHash& GetNextIdentHash() const = 0;

  virtual uint32_t GetTunnelID() const = 0;  // as known at our side

  uint32_t GetCreationTime() const {
    return m_CreationTime;
  }

  void SetCreationTime(
      uint32_t t) {
    m_CreationTime = t;
  }

 private:
  uint32_t m_CreationTime;  // seconds since epoch
};

struct TunnelCreationTimeCmp {
  bool operator() (
      std::shared_ptr<const TunnelBase> t1,
      std::shared_ptr<const TunnelBase> t2) const {
    if (t1->GetCreationTime() != t2->GetCreationTime())
      return t1->GetCreationTime() > t2->GetCreationTime();
    else
      return t1 < t2;
  }
};

}  // namespace tunnel
}  // namespace i2p

#endif  // SRC_CORE_TUNNEL_TUNNEL_BASE_H_
