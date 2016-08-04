include_directories(
  "."
  "../")

set(CORE_SRC
  "Garlic.cc"
  "I2NPProtocol.cc"
  "Identity.cc"
  "LeaseSet.cc"
  "NetDbRequests.cc"
  "NetworkDatabase.cc"
  "Profiling.cc"
  "Reseed.cc"
  "RouterContext.cc"
  "RouterInfo.cc"
  "transport/NTCP.cc"
  "transport/NTCPSession.cc"
  "transport/SSU.cc"
  "transport/SSUData.cc"
  "transport/SSUSession.cc"
  "transport/Transports.cc"
  "transport/UPnP.cc"
  "tunnel/TransitTunnel.cc"
  "tunnel/Tunnel.cc"
  "tunnel/TunnelConfig.cc"
  "tunnel/TunnelEndpoint.cc"
  "tunnel/TunnelGateway.cc"
  "tunnel/TunnelPool.cc"
  "util/Base64.cc"
  "util/Filesystem.cc"
  "util/HTTP.cc"
  "util/MTU.cc"
  "util/ZIP.cc"
  "util/pimpl/Log.cc")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(APPEND CORE_SRC "util/I2PEndian.cc")
endif()

if(WITH_CRYPTOPP)
  set(CRYPTOPP_DIR "crypto/pimpl/cryptopp")
endif()

set(CRYPTO_SRC
  "${CRYPTOPP_DIR}/AES.cc"
  "${CRYPTOPP_DIR}/CryptoConst.cc"
  "${CRYPTOPP_DIR}/DiffieHellman.cc"
  "${CRYPTOPP_DIR}/ElGamal.cc"
  "${CRYPTOPP_DIR}/Hash.cc"
  "${CRYPTOPP_DIR}/Rand.cc"
  "${CRYPTOPP_DIR}/Signature.cc"
  "${CRYPTOPP_DIR}/Tunnel.cc"
  "${CRYPTOPP_DIR}/util/Checksum.cc"
  "${CRYPTOPP_DIR}/util/Compression.cc"
  "${CRYPTOPP_DIR}/util/X509.cc")

if(WITH_SUPERCOP)
  set(EDDSA_DIR "crypto/pimpl/supercop")
  add_subdirectory("crypto/pimpl/supercop/ed25519")
endif()

set(EDDSA_SRC
  "${EDDSA_DIR}/Signature.cc"
  "${EDDSA_DIR}/ed25519/fe_0.cc"
  "${EDDSA_DIR}/ed25519/fe_1.cc"
  "${EDDSA_DIR}/ed25519/fe_add.cc"
  "${EDDSA_DIR}/ed25519/fe_cmov.cc"
  "${EDDSA_DIR}/ed25519/fe_copy.cc"
  "${EDDSA_DIR}/ed25519/fe_frombytes.cc"
  "${EDDSA_DIR}/ed25519/fe_invert.cc"
  "${EDDSA_DIR}/ed25519/fe_isnegative.cc"
  "${EDDSA_DIR}/ed25519/fe_isnonzero.cc"
  "${EDDSA_DIR}/ed25519/fe_mul.cc"
  "${EDDSA_DIR}/ed25519/fe_neg.cc"
  "${EDDSA_DIR}/ed25519/fe_pow22523.cc"
  "${EDDSA_DIR}/ed25519/fe_sq.cc"
  "${EDDSA_DIR}/ed25519/fe_sq2.cc"
  "${EDDSA_DIR}/ed25519/fe_sub.cc"
  "${EDDSA_DIR}/ed25519/fe_tobytes.cc"
  "${EDDSA_DIR}/ed25519/ge_add.cc"
  "${EDDSA_DIR}/ed25519/ge_double_scalarmult.cc"
  "${EDDSA_DIR}/ed25519/ge_frombytes.cc"
  "${EDDSA_DIR}/ed25519/ge_madd.cc"
  "${EDDSA_DIR}/ed25519/ge_msub.cc"
  "${EDDSA_DIR}/ed25519/ge_p1p1_to_p2.cc"
  "${EDDSA_DIR}/ed25519/ge_p1p1_to_p3.cc"
  "${EDDSA_DIR}/ed25519/ge_p2_0.cc"
  "${EDDSA_DIR}/ed25519/ge_p2_dbl.cc"
  "${EDDSA_DIR}/ed25519/ge_p3_0.cc"
  "${EDDSA_DIR}/ed25519/ge_p3_dbl.cc"
  "${EDDSA_DIR}/ed25519/ge_p3_to_cached.cc"
  "${EDDSA_DIR}/ed25519/ge_p3_to_p2.cc"
  "${EDDSA_DIR}/ed25519/ge_p3_tobytes.cc"
  "${EDDSA_DIR}/ed25519/ge_precomp_0.cc"
  "${EDDSA_DIR}/ed25519/ge_scalarmult_base.cc"
  "${EDDSA_DIR}/ed25519/ge_sub.cc"
  "${EDDSA_DIR}/ed25519/ge_tobytes.cc"
  "${EDDSA_DIR}/ed25519/keypair.cc"
  "${EDDSA_DIR}/ed25519/open.cc"
  "${EDDSA_DIR}/ed25519/sc_muladd.cc"
  "${EDDSA_DIR}/ed25519/sc_reduce.cc"
  "${EDDSA_DIR}/ed25519/sign.cc"
  "${EDDSA_DIR}/ed25519/verify.cc")

# Library building
if(WITH_LIBRARY)
  add_library(${CORE_NAME} ${CORE_SRC} ${CRYPTO_SRC} ${EDDSA_SRC})
  target_link_libraries(
    ${CORE_NAME}
    ${Boost_LIBRARIES} ${CryptoPP_LIBRARIES} ${OPENSSL_LIBRARIES}
    ${CPPNETLIB_LIBRARIES} ${DL_LIB})
  install(
    TARGETS ${CORE_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

# vim: noai:ts=2:sw=2
