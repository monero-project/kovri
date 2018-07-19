cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(kovri-core CXX)

add_library(kovri-core
  instance.cc
  router/context.cc
  router/garlic.cc
  router/i2np.cc
  router/identity.cc
  router/info.cc
  router/lease_set.cc
  router/net_db/impl.cc
  router/net_db/requests.cc
  router/profiling.cc
  router/transports/impl.cc
  router/transports/ntcp/server.cc
  router/transports/ntcp/session.cc
  router/transports/ssu/data.cc
  router/transports/ssu/packet.cc
  router/transports/ssu/server.cc
  router/transports/ssu/session.cc
  router/transports/upnp.cc
  router/tunnel/config.cc
  router/tunnel/endpoint.cc
  router/tunnel/gateway.cc
  router/tunnel/impl.cc
  router/tunnel/pool.cc
  router/tunnel/transit.cc
  util/byte_stream.cc
  util/config.cc
  util/exception.cc
  util/filesystem.cc
  util/log.cc
  util/mtu.cc

  instance.h
  router/context.h
  router/garlic.h
  router/i2np.h
  router/identity.h
  router/info.h
  router/lease_set.h
  router/net_db/impl.h
  router/net_db/requests.h
  router/profiling.h
  router/transports/impl.h
  router/transports/ntcp/server.h
  router/transports/ntcp/session.h
  router/transports/session.h
  router/transports/ssu/data.h
  router/transports/ssu/packet.h
  router/transports/ssu/server.h
  router/transports/ssu/session.h
  router/transports/upnp.h
  router/tunnel/base.h
  router/tunnel/config.h
  router/tunnel/endpoint.h
  router/tunnel/gateway.h
  router/tunnel/impl.h
  router/tunnel/pool.h
  router/tunnel/transit.h
  util/buffer.h
  util/byte_stream.h
  util/config.h
  util/exception.h
  util/filesystem.h
  util/log.h
  util/mtu.h
  util/queue.h
  util/tag.h
  util/timestamp.h)

target_include_directories(kovri-core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..) 
target_link_libraries(kovri-core
 PUBLIC 
   Boost::log
   cppnetlib::client-connections
 PRIVATE
   kovri-private
   Boost::program_options)

if(MINGW)
  target_link_libraries(kovri-core PUBLIC iphlpapi)
endif()

if(ANDROID)
  target_sources(kovri-core PRIVATE 
    ../../deps/webrtc/base/ifaddrs-android.cc
    ../../deps/webrtc/base/ifaddrs-android.h)
  set_property(SOURCE ../../deps/webrtc/base/ifaddrs-android.cc APPEND PROPERTY COMPILE_DEFINITIONS WEBRTC_ANDROID)
endif()

if(WITH_CRYPTOPP)
  set(CRYPTOPP_DIR "crypto/impl/cryptopp")
  target_sources(kovri-core PRIVATE
    ${CRYPTOPP_DIR}/aes.cc
    ${CRYPTOPP_DIR}/crypto_const.cc
    ${CRYPTOPP_DIR}/diffie_hellman.cc
    ${CRYPTOPP_DIR}/elgamal.cc
    ${CRYPTOPP_DIR}/hash.cc
    ${CRYPTOPP_DIR}/radix.cc
    ${CRYPTOPP_DIR}/rand.cc
    ${CRYPTOPP_DIR}/signature.cc
    ${CRYPTOPP_DIR}/tunnel.cc
    ${CRYPTOPP_DIR}/util/checksum.cc
    ${CRYPTOPP_DIR}/util/compression.cc
    ${CRYPTOPP_DIR}/util/misc.cc
    ${CRYPTOPP_DIR}/util/x509.cc
    crypto/aes.h
    crypto/diffie_hellman.h
    crypto/elgamal.h
    crypto/hash.h
    crypto/hmac.h    
    crypto/radix.h
    crypto/rand.h
    crypto/signature.h
    crypto/signature_base.h
    crypto/tunnel.h
    crypto/util/checksum.h
    crypto/util/compression.h
    crypto/util/misc.h
    crypto/util/x509.h
    ${CRYPTOPP_DIR}/aesni_macros.h
    ${CRYPTOPP_DIR}/crypto_const.h)
endif()

# Add definition for our implementation (must be here or in root recipe)
target_link_libraries(kovri-core PRIVATE libminiupnpc-static)

if (COMMAND cotire)
  set_target_properties(kovri-core PROPERTIES COTIRE_PREFIX_HEADER_INCLUDE_PATH "${CMAKE_SOURCE_DIR}/deps")
  cotire(kovri-core)
endif()

# Library building
install(
  TARGETS kovri-core
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

# vim: noai:ts=2:sw=2
