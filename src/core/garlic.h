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

#ifndef SRC_CORE_GARLIC_H_
#define SRC_CORE_GARLIC_H_
#include <array>
#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "i2np_protocol.h"
#include "identity.h"
#include "lease_set.h"
#include "crypto/aes.h"
#include "crypto/rand.h"
#include "util/queue.h"

namespace i2p {
namespace garlic {

enum GarlicDeliveryType {
  eGarlicDeliveryTypeLocal = 0,
  eGarlicDeliveryTypeDestination = 1,
  eGarlicDeliveryTypeRouter = 2,
  eGarlicDeliveryTypeTunnel = 3
};

#pragma pack(1)
struct ElGamalBlock {
  ElGamalBlock() {
    // Spec defines padding as CSPRNG radomized
    i2p::crypto::RandBytes(padding.data(), padding.size());
  }
  std::array<std::uint8_t, 32> session_key;
  std::array<std::uint8_t, 32> pre_IV;
  std::array<std::uint8_t, 158> padding;
};
#pragma pack()

const int INCOMING_TAGS_EXPIRATION_TIMEOUT = 960;  // 16 minutes
const int OUTGOING_TAGS_EXPIRATION_TIMEOUT = 720;  // 12 minutes
const int LEASET_CONFIRMATION_TIMEOUT = 4000;  // in milliseconds

struct SessionTag
    : public i2p::data::Tag<32> {
  SessionTag(
      const std::uint8_t* buf,
      std::uint32_t ts = 0)
    : Tag<32>(buf),
      creation_time(ts) {}

  SessionTag() = default;

  SessionTag(
      const SessionTag&) = default;

  SessionTag& operator=(
      const SessionTag&) = default;

#ifndef _WIN32
  SessionTag(
      SessionTag&&) = default;

  SessionTag& operator=(
      SessionTag&&) = default;
#endif

  std::uint32_t creation_time;  // seconds since epoch
};

class GarlicDestination;
class GarlicRoutingSession
    : public std::enable_shared_from_this<GarlicRoutingSession> {
 public:
  GarlicRoutingSession(
      GarlicDestination* owner,
      std::shared_ptr<const i2p::data::RoutingDestination> destination,
      int num_tags,
      bool attach_lease_set);

  GarlicRoutingSession(
      const std::uint8_t* sessionKey,
      const SessionTag& sessionTag);  // one time encryption

  ~GarlicRoutingSession();

  std::shared_ptr<I2NPMessage> WrapSingleMessage(
      std::shared_ptr<const I2NPMessage> msg);

  void MessageConfirmed(
      std::uint32_t msg_ID);

  bool CleanupExpiredTags();  // returns true if something left

  void SetLeaseSetUpdated() {
    if (m_LeaseSetUpdateStatus != eLeaseSetDoNotSend)
      m_LeaseSetUpdateStatus = eLeaseSetUpdated;
  }

 private:
  enum LeaseSetUpdateStatus {
    eLeaseSetUpToDate = 0,
    eLeaseSetUpdated,
    eLeaseSetSubmitted,
    eLeaseSetDoNotSend
  };

  struct UnconfirmedTags {
    explicit UnconfirmedTags(int n)
        : num_tags(n),
          tags_creation_time(0) {
            session_tags = std::make_unique<SessionTag[]>(num_tags);
          }
    ~UnconfirmedTags() {}
    int num_tags;
    std::unique_ptr<SessionTag[]> session_tags;
    std::uint32_t tags_creation_time;
  };

 private:
  std::size_t CreateAESBlock(
      std::uint8_t* buf,
      std::shared_ptr<const I2NPMessage> msg);

  std::size_t CreateGarlicPayload(
      std::uint8_t* payload,
      std::shared_ptr<const I2NPMessage> msg,
      UnconfirmedTags* new_tags);

  std::size_t CreateGarlicClove(
      std::uint8_t* buf,
      std::shared_ptr<const I2NPMessage> msg,
      bool is_destination);

  std::size_t CreateDeliveryStatusClove(
      std::uint8_t* buf,
      std::uint32_t msg_ID);

  void TagsConfirmed(
      std::uint32_t msg_ID);

  UnconfirmedTags* GenerateSessionTags();

 private:
  std::unique_ptr<GarlicDestination> m_Owner;
  std::shared_ptr<const i2p::data::RoutingDestination> m_Destination;
  i2p::crypto::AESKey m_SessionKey;
  std::list<SessionTag> m_SessionTags;
  int m_NumTags;
  std::map<std::uint32_t, UnconfirmedTags *> m_UnconfirmedTagsMsgs;

  LeaseSetUpdateStatus m_LeaseSetUpdateStatus;
  std::uint32_t m_LeaseSetUpdateMsgID;
  std::uint64_t m_LeaseSetSubmissionTime;  // in milliseconds

  i2p::crypto::CBCEncryption m_Encryption;
};

class GarlicDestination
    : public i2p::data::LocalDestination {
 public:
  GarlicDestination()
      : m_LastTagsCleanupTime(0) {}

  ~GarlicDestination();

  std::shared_ptr<GarlicRoutingSession> GetRoutingSession(
      std::shared_ptr<const i2p::data::RoutingDestination> destination,
      bool attach_lease_set);

  void CleanupRoutingSessions();

  void RemoveCreatedSession(
      std::uint32_t msg_ID);

  std::shared_ptr<I2NPMessage> WrapMessage(
      std::shared_ptr<const i2p::data::RoutingDestination> destination,
      std::shared_ptr<I2NPMessage> msg,
      bool attach_lease_set = false);

  void AddSessionKey(
      const std::uint8_t* key,
      const std::uint8_t* tag);  // one tag

  virtual bool SubmitSessionKey(
      const std::uint8_t* key,
      const std::uint8_t* tag);  // from different thread

  void DeliveryStatusSent(
      std::shared_ptr<GarlicRoutingSession> session,
      std::uint32_t msg_ID);

  virtual void ProcessGarlicMessage(std::shared_ptr<I2NPMessage> msg);
  virtual void ProcessDeliveryStatusMessage(std::shared_ptr<I2NPMessage> msg);
  virtual void SetLeaseSetUpdated();

  // TODO(unassigned): ???
  virtual std::shared_ptr<const i2p::data::LeaseSet> GetLeaseSet() = 0;
  virtual std::shared_ptr<i2p::tunnel::TunnelPool> GetTunnelPool() const = 0;

  virtual void HandleI2NPMessage(
      const std::uint8_t* buf,
      std::size_t len,
      std::shared_ptr<i2p::tunnel::InboundTunnel> from) = 0;

 protected:
  void HandleGarlicMessage(std::shared_ptr<I2NPMessage> msg);
  void HandleDeliveryStatusMessage(std::shared_ptr<I2NPMessage> msg);

 private:
  void HandleAESBlock(
      std::uint8_t* buf,
      std::size_t len,
      std::shared_ptr<i2p::crypto::CBCDecryption> decryption,
      std::shared_ptr<i2p::tunnel::InboundTunnel> from);

  void HandleGarlicPayload(
      std::uint8_t* buf,
      std::size_t len,
      std::shared_ptr<i2p::tunnel::InboundTunnel> from);

 private:
  // outgoing sessions
  std::mutex m_SessionsMutex;
  std::map<i2p::data::IdentHash,
           std::shared_ptr<GarlicRoutingSession>> m_Sessions;
  // incoming
  std::map<SessionTag,
           std::shared_ptr<i2p::crypto::CBCDecryption>> m_Tags;
  std::uint32_t m_LastTagsCleanupTime;
  // DeliveryStatus  (msg_ID -> session)
  std::map<uint32_t,
           std::shared_ptr<GarlicRoutingSession>> m_CreatedSessions;
};

}  // namespace garlic
}  // namespace i2p

#endif  // SRC_CORE_GARLIC_H_
