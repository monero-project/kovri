/**
 * Copyright (c) 2013-2016, The Kovri I2P Router Project
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
 *
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project
 */

#ifndef SRC_CORE_TRANSPORT_SSUDATA_H_
#define SRC_CORE_TRANSPORT_SSUDATA_H_

#include <boost/asio.hpp>

#include <inttypes.h>
#include <string.h>

#include <map>
#include <memory>
#include <set>
#include <vector>

#include "I2NPProtocol.h"
#include "Identity.h"
#include "RouterInfo.h"
#include "SSUPacket.h"

namespace i2p {
namespace transport {

/// @enum SSUDuration
/// @brief Constants used to represent various aspects
///   of duration used during SSU activity
enum struct SSUDuration : const std::size_t {
  ResendInterval = 3,  // Seconds
  MaxResends = 5,
  DecayInterval = 20,  // Number of message IDs we store for duplicates check
  IncompleteMessagesCleanupTimeout = 30,  // Seconds
};

struct Fragment {
  int fragmentNum;
  size_t len;
  bool isLast;
  uint8_t buf[static_cast<std::size_t>(SSUSize::PacketMaxIPv4) + 18];  // use biggest
  Fragment() = default;
  Fragment(
      int n,
      const uint8_t* b,
      int l,
      bool last)
      : fragmentNum(n),
        len(l),
        isLast(last) {
          memcpy(buf, b, len);
        }
};

struct FragmentCmp {
  bool operator() (
      const std::unique_ptr<Fragment>& f1,
      const std::unique_ptr<Fragment>& f2) const {
    return f1->fragmentNum < f2->fragmentNum;
  }
};

struct IncompleteMessage {
  std::shared_ptr<I2NPMessage> msg;
  int nextFragmentNum;
  uint32_t lastFragmentInsertTime;  // in seconds
  std::set<std::unique_ptr<Fragment>, FragmentCmp> savedFragments;

  IncompleteMessage(
      std::shared_ptr<I2NPMessage> m)
      : msg(m),
        nextFragmentNum(0),
        lastFragmentInsertTime(0) {}

  void AttachNextFragment(
      const uint8_t* fragment,
      size_t fragmentSize);
};

struct SentMessage {
  std::vector<std::unique_ptr<Fragment> > fragments;
  uint32_t nextResendTime;  // in seconds
  std::size_t numResends;
};

class SSUSession;
class SSUData {
 public:
  SSUData(
      SSUSession& session);
  ~SSUData();

  void Start();

  void Stop();

  void ProcessMessage(
      uint8_t* buf,
      size_t len);

  void FlushReceivedMessage();

  void Send(
      std::shared_ptr<i2p::I2NPMessage> msg);

  void UpdatePacketSize(
      const i2p::data::IdentHash& remoteIdent);

 private:
  void SendMsgAck(
      uint32_t msgID);

  void SendFragmentAck(
      uint32_t msgID,
      int fragmentNum);

  void ProcessAcks(
      uint8_t *& buf,
      uint8_t flag);

  void ProcessFragments(
      uint8_t * buf);

  void ProcessSentMessageAck(
      uint32_t msgID);

  void ScheduleResend();

  void HandleResendTimer(
      const boost::system::error_code& ecode);

  void ScheduleDecay();

  void HandleDecayTimer(
      const boost::system::error_code& ecode);

  void ScheduleIncompleteMessagesCleanup();

  void HandleIncompleteMessagesCleanupTimer(
      const boost::system::error_code& ecode);

  void AdjustPacketSize(
      const i2p::data::RouterInfo& remoteRouter);

 private:
  SSUSession& m_Session;
  std::map<uint32_t, std::unique_ptr<IncompleteMessage> > m_IncompleteMessages;
  std::map<uint32_t, std::unique_ptr<SentMessage> > m_SentMessages;
  std::set<uint32_t> m_ReceivedMessages;
  boost::asio::deadline_timer m_ResendTimer,
                              m_DecayTimer,
                              m_IncompleteMessagesCleanupTimer;
  int m_MaxPacketSize, m_PacketSize;
  i2p::I2NPMessagesHandler m_Handler;
};

}  // namespace transport
}  // namespace i2p

#endif  // SRC_CORE_TRANSPORT_SSUDATA_H_

