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

#ifndef SRC_CORE_TRANSPORT_SSU_DATA_H_
#define SRC_CORE_TRANSPORT_SSU_DATA_H_

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <vector>

#include "i2np_protocol.h"
#include "identity.h"
#include "router_info.h"
#include "ssu_packet.h"

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
  ConnectTimeout = 5,  // Seconds
  TerminationTimeout = 330,  // 5 1/2 minutes
  KeepAliveInterval = 30,  // Seconds
  PeerTestTimeout = 60,  // Seconds
  ToIntroducerSessionDuration = 3600,  // 1 hour
};

struct Fragment {
  Fragment() = default;

  Fragment(
      std::size_t num,
      const std::uint8_t* buf,
      std::size_t last_len,
      bool last)
      : fragment_num(num),
        len(last_len),
        is_last(last) {
          memcpy(buffer.data(), buf, len);
        }

  std::size_t fragment_num, len;
  bool is_last;
  // TODO(unassigned): document 18 and why ipv4
  std::array<std::uint8_t, static_cast<std::size_t>(SSUSize::PacketMaxIPv4) + 18> buffer;
};

struct FragmentCmp {
  bool operator() (
      const std::unique_ptr<Fragment>& f1,
      const std::unique_ptr<Fragment>& f2) const {
    return f1->fragment_num < f2->fragment_num;
  }
};

struct IncompleteMessage {
  IncompleteMessage(
      std::shared_ptr<I2NPMessage> m)
      : msg(m),
        next_fragment_num(0),
        last_fragment_insert_time(0) {}

  void AttachNextFragment(
      const std::uint8_t* fragment,
      std::size_t fragment_size);

  std::shared_ptr<I2NPMessage> msg;
  std::size_t next_fragment_num;
  std::uint32_t last_fragment_insert_time;  // in seconds
  std::set<std::unique_ptr<Fragment>, FragmentCmp> saved_fragments;
};

struct SentMessage {
  std::vector<std::unique_ptr<Fragment>> fragments;
  std::uint32_t next_resend_time;  // in seconds
  std::size_t num_resends;
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
      std::uint8_t* buf,
      std::size_t len);

  void FlushReceivedMessage();

  void Send(
      std::shared_ptr<i2p::I2NPMessage> msg);

  void UpdatePacketSize(
      const i2p::data::IdentHash& remote_ident);

 private:
  void SendMsgACK(
      std::uint32_t msg_id);

  void SendFragmentACK(
      std::uint32_t msg_id,
      std::size_t fragment_num);

  void ProcessACKs(
      std::uint8_t*& buf,
      std::uint8_t flag);

  void ProcessFragments(
      std::uint8_t * buf);

  void ProcessSentMessageACK(
      std::uint32_t msg_id);

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
  std::map<std::uint32_t, std::unique_ptr<IncompleteMessage>> m_IncompleteMessages;
  std::map<std::uint32_t, std::unique_ptr<SentMessage>> m_SentMessages;
  std::set<std::uint32_t> m_ReceivedMessages;
  boost::asio::deadline_timer m_ResendTimer, m_DecayTimer,
                              m_IncompleteMessagesCleanupTimer;
  std::size_t m_MaxPacketSize, m_PacketSize;
  i2p::I2NPMessagesHandler m_Handler;
};

}  // namespace transport
}  // namespace i2p

#endif  // SRC_CORE_TRANSPORT_SSU_DATA_H_
