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

#ifndef SRC_CLIENT_DESTINATION_H_
#define SRC_CLIENT_DESTINATION_H_

#include <boost/asio.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include "client/api/datagram.h"
#include "client/api/streaming.h"

#include "core/router/garlic.h"
#include "core/router/identity.h"
#include "core/router/lease_set.h"
#include "core/router/net_db/net_db.h"
#include "core/router/tunnel/pool.h"

namespace kovri {
namespace client {

const std::uint8_t PROTOCOL_TYPE_STREAMING = 6;
const std::uint8_t PROTOCOL_TYPE_DATAGRAM = 17;
const std::uint8_t PROTOCOL_TYPE_RAW = 18;
const int PUBLISH_CONFIRMATION_TIMEOUT = 5;  // in seconds
const int LEASESET_REQUEST_TIMEOUT = 5;  // in seconds
const int MAX_LEASESET_REQUEST_TIMEOUT = 40;  // in seconds
const int MAX_NUM_FLOODFILLS_PER_REQUEST = 7;
const int DESTINATION_CLEANUP_TIMEOUT = 20;  // in minutes

// I2CP
const char I2CP_PARAM_INBOUND_TUNNEL_LENGTH[] = "inbound.length";
const int DEFAULT_INBOUND_TUNNEL_LENGTH = 3;
const char I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH[] = "outbound.length";
const int DEFAULT_OUTBOUND_TUNNEL_LENGTH = 3;
const char I2CP_PARAM_INBOUND_TUNNELS_QUANTITY[] = "inbound.quantity";
const int DEFAULT_INBOUND_TUNNELS_QUANTITY = 5;
const char I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY[] = "outbound.quantity";
const int DEFAULT_OUTBOUND_TUNNELS_QUANTITY = 5;
const char I2CP_PARAM_EXPLICIT_PEERS[] = "explicitPeers";
const int STREAM_REQUEST_TIMEOUT = 60;  // in seconds

typedef std::function<void (std::shared_ptr<kovri::client::Stream> stream)> StreamRequestComplete;

class ClientDestination : public kovri::core::GarlicDestination {
  typedef std::function<void (std::shared_ptr<kovri::core::LeaseSet> leaseSet)> RequestComplete;
  // leaseSet = nullptr means not found
  struct LeaseSetRequest {
    LeaseSetRequest(
        boost::asio::io_service& service)
        : request_time(0),
          request_timeout_timer(service) {}
    std::set<kovri::core::IdentHash> excluded;
    std::uint64_t request_time;
    boost::asio::deadline_timer request_timeout_timer;
    RequestComplete request_complete;
  };

 public:
  ClientDestination(
      const kovri::core::PrivateKeys& keys,
      bool is_public,
      const std::map<std::string, std::string>* params = nullptr);

  ~ClientDestination();

  virtual void Start();

  virtual void Stop();

  bool IsRunning() const {
    return m_IsRunning;
  }

  boost::asio::io_service& GetService() {
    return m_Service;
  }

  std::shared_ptr<kovri::core::TunnelPool> GetTunnelPool() {
    return m_Pool;
  }

  bool IsReady() const {
    return m_LeaseSet &&
           m_LeaseSet->HasNonExpiredLeases() &&
           m_Pool->GetOutboundTunnels().size() > 0;
  }

  std::shared_ptr<const kovri::core::LeaseSet> FindLeaseSet(
      const kovri::core::IdentHash& ident);

  bool RequestDestination(
      const kovri::core::IdentHash& dest,
      RequestComplete request_complete = nullptr);

  // streaming
  std::shared_ptr<kovri::client::StreamingDestination> CreateStreamingDestination(
      int port);  // additional

  std::shared_ptr<kovri::client::StreamingDestination> GetStreamingDestination(
      int port = 0) const;

  // following methods operate with default streaming destination
  void CreateStream(
      StreamRequestComplete stream_request_complete,
      const kovri::core::IdentHash& dest,
      int port = 0);

  std::shared_ptr<kovri::client::Stream> CreateStream(
      std::shared_ptr<const kovri::core::LeaseSet> remote,
      int port = 0);

  void AcceptStreams(
      const kovri::client::StreamingDestination::Acceptor& acceptor);

  void StopAcceptingStreams();

  bool IsAcceptingStreams() const;

  // datagram
  DatagramDestination* GetDatagramDestination() const {
    return m_DatagramDestination;
  }

  DatagramDestination* CreateDatagramDestination();

  // implements LocalDestination
  const kovri::core::PrivateKeys& GetPrivateKeys() const {
    return m_Keys;
  }

  const std::uint8_t* GetEncryptionPrivateKey() const {
    return m_EncryptionPrivateKey;
  }

  const std::uint8_t* GetEncryptionPublicKey() const {
    return m_EncryptionPublicKey;
  }

  // implements GarlicDestination
  std::shared_ptr<const kovri::core::LeaseSet> GetLeaseSet();

  std::shared_ptr<kovri::core::TunnelPool> GetTunnelPool() const {
    return m_Pool;
  }

  void HandleI2NPMessage(
      const std::uint8_t* buf,
      std::size_t len,
      std::shared_ptr<kovri::core::InboundTunnel> from);

  // override GarlicDestination
  bool SubmitSessionKey(
      const std::uint8_t* key,
      const std::uint8_t* tag);

  void ProcessGarlicMessage(
      std::shared_ptr<I2NPMessage> msg);

  void ProcessDeliveryStatusMessage(
      std::shared_ptr<I2NPMessage> msg);

  void SetLeaseSetUpdated();

  // I2CP
  void HandleDataMessage(
      const std::uint8_t* buf,
      std::size_t len);

 private:
  void Run();

  void UpdateLeaseSet();

  void Publish();

  void HandlePublishConfirmationTimer(
      const boost::system::error_code& ecode);

  void HandleDatabaseStoreMessage(
      const std::uint8_t* buf,
      std::size_t len);

  void HandleDatabaseSearchReplyMessage(
      const std::uint8_t* buf,
      std::size_t len);

  void HandleDeliveryStatusMessage(
      std::shared_ptr<I2NPMessage> msg);

  void RequestLeaseSet(
      const kovri::core::IdentHash& dest,
      RequestComplete request_complete);

  bool SendLeaseSetRequest(
      const kovri::core::IdentHash& dest,
      std::shared_ptr<const kovri::core::RouterInfo> next_floodfill,
      LeaseSetRequest* request);

  void HandleRequestTimoutTimer(
      const boost::system::error_code& ecode,
      const kovri::core::IdentHash& dest);

  void HandleCleanupTimer(
      const boost::system::error_code& ecode);

  void CleanupRemoteLeaseSets();

 private:
  volatile bool m_IsRunning;
  std::unique_ptr<std::thread> m_Thread;
  boost::asio::io_service m_Service;
  boost::asio::io_service::work m_Work;

  kovri::core::PrivateKeys m_Keys;
  std::uint8_t m_EncryptionPublicKey[256], m_EncryptionPrivateKey[256];

  std::map<kovri::core::IdentHash,
           std::shared_ptr<kovri::core::LeaseSet>> m_RemoteLeaseSets;

  std::map<kovri::core::IdentHash,
           LeaseSetRequest *> m_LeaseSetRequests;

  std::shared_ptr<kovri::core::TunnelPool> m_Pool;
  std::shared_ptr<kovri::core::LeaseSet> m_LeaseSet;

  bool m_IsPublic;

  std::uint32_t m_PublishReplyToken;
  std::set<kovri::core::IdentHash> m_ExcludedFloodfills;  // for publishing

  std::shared_ptr<kovri::client::StreamingDestination> m_StreamingDestination;  // default

  std::map<std::uint16_t,
           std::shared_ptr<kovri::client::StreamingDestination>> m_StreamingDestinationsByPorts;

  DatagramDestination* m_DatagramDestination;

  boost::asio::deadline_timer m_PublishConfirmationTimer, m_CleanupTimer;
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_DESTINATION_H_
