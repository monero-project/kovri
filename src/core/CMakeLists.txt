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
  util/mtu.cc)

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
  target_sources(kovri-core PRIVATE ../../deps/webrtc/base/ifaddrs-android.cc)
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
    ${CRYPTOPP_DIR}/util/x509.cc)
endif()

if(WITH_SUPERCOP)
  set(EDDSA_DIR "crypto/impl/supercop")
  target_sources(kovri-core PRIVATE 
    ${EDDSA_DIR}/signature.cc
    ${EDDSA_DIR}/ed25519/fe_0.cc
    ${EDDSA_DIR}/ed25519/fe_1.cc
    ${EDDSA_DIR}/ed25519/fe_add.cc
    ${EDDSA_DIR}/ed25519/fe_cmov.cc
    ${EDDSA_DIR}/ed25519/fe_copy.cc
    ${EDDSA_DIR}/ed25519/fe_frombytes.cc
    ${EDDSA_DIR}/ed25519/fe_invert.cc
    ${EDDSA_DIR}/ed25519/fe_isnegative.cc
    ${EDDSA_DIR}/ed25519/fe_isnonzero.cc
    ${EDDSA_DIR}/ed25519/fe_mul.cc
    ${EDDSA_DIR}/ed25519/fe_neg.cc
    ${EDDSA_DIR}/ed25519/fe_pow22523.cc
    ${EDDSA_DIR}/ed25519/fe_sq.cc
    ${EDDSA_DIR}/ed25519/fe_sq2.cc
    ${EDDSA_DIR}/ed25519/fe_sub.cc
    ${EDDSA_DIR}/ed25519/fe_tobytes.cc
    ${EDDSA_DIR}/ed25519/ge_add.cc
    ${EDDSA_DIR}/ed25519/ge_double_scalarmult.cc
    ${EDDSA_DIR}/ed25519/ge_frombytes.cc
    ${EDDSA_DIR}/ed25519/ge_madd.cc
    ${EDDSA_DIR}/ed25519/ge_msub.cc
    ${EDDSA_DIR}/ed25519/ge_p1p1_to_p2.cc
    ${EDDSA_DIR}/ed25519/ge_p1p1_to_p3.cc
    ${EDDSA_DIR}/ed25519/ge_p2_0.cc
    ${EDDSA_DIR}/ed25519/ge_p2_dbl.cc
    ${EDDSA_DIR}/ed25519/ge_p3_0.cc
    ${EDDSA_DIR}/ed25519/ge_p3_dbl.cc
    ${EDDSA_DIR}/ed25519/ge_p3_to_cached.cc
    ${EDDSA_DIR}/ed25519/ge_p3_to_p2.cc
    ${EDDSA_DIR}/ed25519/ge_p3_tobytes.cc
    ${EDDSA_DIR}/ed25519/ge_precomp_0.cc
    ${EDDSA_DIR}/ed25519/ge_scalarmult_base.cc
    ${EDDSA_DIR}/ed25519/ge_sub.cc
    ${EDDSA_DIR}/ed25519/ge_tobytes.cc
    ${EDDSA_DIR}/ed25519/keypair.cc
    ${EDDSA_DIR}/ed25519/open.cc
    ${EDDSA_DIR}/ed25519/sc_muladd.cc
    ${EDDSA_DIR}/ed25519/sc_reduce.cc
    ${EDDSA_DIR}/ed25519/sign.cc
    ${EDDSA_DIR}/ed25519/verify.cc)
endif()


# Library building
install(
  TARGETS ${CORE_NAME}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

# vim: noai:ts=2:sw=2
