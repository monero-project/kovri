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

#ifndef SRC_CLIENT_DATAGRAM_H_
#define SRC_CLIENT_DATAGRAM_H_

#include <inttypes.h>

#include <functional>
#include <map>
#include <memory>

#include "i2np_protocol.h"
#include "identity.h"
#include "lease_set.h"

namespace i2p {
namespace client { class ClientDestination; }
namespace datagram {

const size_t MAX_DATAGRAM_SIZE = 32768;

class DatagramDestination {
  typedef std::function<void (
      const i2p::data::IdentityEx& from,
      uint16_t fromPort,
      uint16_t toPort,
      const uint8_t* buf,
      size_t len)>
    Receiver;

 public:
  explicit DatagramDestination(
      i2p::client::ClientDestination& owner);
  ~DatagramDestination() {}

  void SendDatagramTo(
      const uint8_t* payload,
      size_t len,
      const i2p::data::IdentHash& ident,
      uint16_t fromPort = 0,
      uint16_t toPort = 0);

  void HandleDataMessagePayload(
      uint16_t fromPort,
      uint16_t toPort,
      const uint8_t* buf,
      size_t len);

  void SetReceiver(
      const Receiver& receiver) {
    m_Receiver = receiver;
  }

  void ResetReceiver() {
    m_Receiver = nullptr;
  }

  void SetReceiver(
      const Receiver& receiver,
      uint16_t port) {
    m_ReceiversByPorts[port] = receiver;
  }

  void ResetReceiver(
      uint16_t port) {
    m_ReceiversByPorts.erase(port);
  }

 private:
  void HandleLeaseSetRequestComplete(
      std::shared_ptr<i2p::data::LeaseSet> leaseSet,
      I2NPMessage* msg);

  I2NPMessage* CreateDataMessage(
      const uint8_t* payload,
      size_t len,
      uint16_t fromPort,
      uint16_t toPort);

  void SendMsg(
      I2NPMessage* msg,
      std::shared_ptr<const i2p::data::LeaseSet> remote);

  void HandleDatagram(
      uint16_t fromPort,
      uint16_t toPort,
      const uint8_t* buf,
      size_t len);

 private:
  i2p::client::ClientDestination& m_Owner;
  Receiver m_Receiver;  // default
  std::map<uint16_t, Receiver> m_ReceiversByPorts;
};

}  // namespace datagram
}  // namespace i2p

#endif  // SRC_CLIENT_DATAGRAM_H_
