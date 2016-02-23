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

#ifndef SRC_CORE_GARLIC_H_
#define SRC_CORE_GARLIC_H_

#include <cryptopp/osrng.h>

#include <inttypes.h>

#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "I2NPProtocol.h"
#include "Identity.h"
#include "LeaseSet.h"
#include "crypto/AES.h"
#include "util/Queue.h"

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
  uint8_t sessionKey[32];
  uint8_t preIV[32];
  uint8_t padding[158];
};
#pragma pack()

const int INCOMING_TAGS_EXPIRATION_TIMEOUT = 960;  // 16 minutes
const int OUTGOING_TAGS_EXPIRATION_TIMEOUT = 720;  // 12 minutes
const int LEASET_CONFIRMATION_TIMEOUT = 4000;  // in milliseconds

struct SessionTag: public i2p::data::Tag<32> {
  SessionTag(
      const uint8_t* buf,
      uint32_t ts = 0)
    : Tag<32>(buf),
      creationTime(ts) {}
  SessionTag() = default;
  SessionTag(const SessionTag&) = default;
  SessionTag& operator=(const SessionTag&) = default;
#ifndef _WIN32
  SessionTag(SessionTag&&) = default;
  SessionTag& operator=(SessionTag&&) = default;
#endif
  uint32_t creationTime;  // seconds since epoch
};

class GarlicDestination;
class GarlicRoutingSession
    : public std::enable_shared_from_this<GarlicRoutingSession> {
  enum LeaseSetUpdateStatus {
    eLeaseSetUpToDate = 0,
    eLeaseSetUpdated,
    eLeaseSetSubmitted,
    eLeaseSetDoNotSend
  };

  struct UnconfirmedTags {
    explicit UnconfirmedTags(int n)
        : numTags(n),
          tagsCreationTime(0) {
            sessionTags = new SessionTag[numTags];
          }
    ~UnconfirmedTags() { delete[] sessionTags; }
    int numTags;
    SessionTag * sessionTags;
    uint32_t tagsCreationTime;
  };

 public:
  GarlicRoutingSession(
      GarlicDestination* owner,
      std::shared_ptr<const i2p::data::RoutingDestination> destination,
      int numTags,
      bool attachLeaseSet);
  GarlicRoutingSession(
      const uint8_t* sessionKey,
      const SessionTag& sessionTag);  // one time encryption
  ~GarlicRoutingSession();

  std::shared_ptr<I2NPMessage> WrapSingleMessage(
      std::shared_ptr<const I2NPMessage> msg);

  void MessageConfirmed(uint32_t msgID);

  bool CleanupExpiredTags();  // returns true if something left

  void SetLeaseSetUpdated() {
    if (m_LeaseSetUpdateStatus != eLeaseSetDoNotSend)
      m_LeaseSetUpdateStatus = eLeaseSetUpdated;
  }

 private:
  size_t CreateAESBlock(
      uint8_t* buf,
      std::shared_ptr<const I2NPMessage> msg);

  size_t CreateGarlicPayload(
      uint8_t* payload,
      std::shared_ptr<const I2NPMessage> msg,
      UnconfirmedTags * newTags);

  size_t CreateGarlicClove(
      uint8_t* buf,
      std::shared_ptr<const I2NPMessage> msg,
      bool isDestination);

  size_t CreateDeliveryStatusClove(
      uint8_t* buf,
      uint32_t msgID);

  void TagsConfirmed(uint32_t msgID);
  UnconfirmedTags* GenerateSessionTags();

 private:
  GarlicDestination* m_Owner;
  std::shared_ptr<const i2p::data::RoutingDestination> m_Destination;
  i2p::crypto::AESKey m_SessionKey;
  std::list<SessionTag> m_SessionTags;
  int m_NumTags;
  std::map<uint32_t, UnconfirmedTags *> m_UnconfirmedTagsMsgs;

  LeaseSetUpdateStatus m_LeaseSetUpdateStatus;
  uint32_t m_LeaseSetUpdateMsgID;
  uint64_t m_LeaseSetSubmissionTime;  // in milliseconds

  i2p::crypto::CBCEncryption m_Encryption;
  CryptoPP::AutoSeededRandomPool m_Rnd;
};

class GarlicDestination : public i2p::data::LocalDestination {
 public:
  GarlicDestination() : m_LastTagsCleanupTime(0) {}
  ~GarlicDestination();

  std::shared_ptr<GarlicRoutingSession> GetRoutingSession(
      std::shared_ptr<const i2p::data::RoutingDestination> destination,
      bool attachLeaseSet);

  void CleanupRoutingSessions();

  void RemoveCreatedSession(uint32_t msgID);

  std::shared_ptr<I2NPMessage> WrapMessage(
      std::shared_ptr<const i2p::data::RoutingDestination> destination,
      std::shared_ptr<I2NPMessage> msg,
      bool attachLeaseSet = false);

  void AddSessionKey(
      const uint8_t* key,
      const uint8_t* tag);  // one tag

  virtual bool SubmitSessionKey(
      const uint8_t* key,
      const uint8_t* tag);  // from different thread

  void DeliveryStatusSent(
      std::shared_ptr<GarlicRoutingSession> session,
      uint32_t msgID);

  virtual void ProcessGarlicMessage(std::shared_ptr<I2NPMessage> msg);
  virtual void ProcessDeliveryStatusMessage(std::shared_ptr<I2NPMessage> msg);
  virtual void SetLeaseSetUpdated();

  // TODO(unassigned): ???
  virtual std::shared_ptr<const i2p::data::LeaseSet> GetLeaseSet() = 0;
  virtual std::shared_ptr<i2p::tunnel::TunnelPool> GetTunnelPool() const = 0;

  virtual void HandleI2NPMessage(
      const uint8_t* buf,
      size_t len,
      std::shared_ptr<i2p::tunnel::InboundTunnel> from) = 0;

 protected:
  void HandleGarlicMessage(std::shared_ptr<I2NPMessage> msg);
  void HandleDeliveryStatusMessage(std::shared_ptr<I2NPMessage> msg);

 private:
  void HandleAESBlock(
      uint8_t* buf,
      size_t len,
      std::shared_ptr<i2p::crypto::CBCDecryption> decryption,
      std::shared_ptr<i2p::tunnel::InboundTunnel> from);

  void HandleGarlicPayload(
      uint8_t* buf,
      size_t len,
      std::shared_ptr<i2p::tunnel::InboundTunnel> from);

 private:
  // outgoing sessions
  std::mutex m_SessionsMutex;
  std::map<i2p::data::IdentHash,
    std::shared_ptr<GarlicRoutingSession> > m_Sessions;
  // incoming
  std::map<SessionTag,
    std::shared_ptr<i2p::crypto::CBCDecryption> > m_Tags;
  uint32_t m_LastTagsCleanupTime;
  // DeliveryStatus
  std::map<uint32_t,
    std::shared_ptr<GarlicRoutingSession> > m_CreatedSessions;  // msgID -> session
};

}  // namespace garlic
}  // namespace i2p

#endif  // SRC_CORE_GARLIC_H_
