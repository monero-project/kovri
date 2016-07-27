include_directories(
  "."
  "../")

set(CORE_SRC
  "Garlic.cpp"
  "I2NPProtocol.cpp"
  "Identity.cpp"
  "LeaseSet.cpp"
  "NetDbRequests.cpp"
  "NetworkDatabase.cpp"
  "Profiling.cpp"
  "Reseed.cpp"
  "RouterContext.cpp"
  "RouterInfo.cpp"
  "transport/NTCP.cpp"
  "transport/NTCPSession.cpp"
  "transport/SSU.cpp"
  "transport/SSUData.cpp"
  "transport/SSUSession.cpp"
  "transport/Transports.cpp"
  "transport/UPnP.cpp"
  "tunnel/TransitTunnel.cpp"
  "tunnel/Tunnel.cpp"
  "tunnel/TunnelConfig.cpp"
  "tunnel/TunnelEndpoint.cpp"
  "tunnel/TunnelGateway.cpp"
  "tunnel/TunnelPool.cpp"
  "util/Base64.cpp"
  "util/Filesystem.cpp"
  "util/HTTP.cpp"
  "util/MTU.cpp"
  "util/ZIP.cpp"
  "util/pimpl/Log.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(APPEND CORE_SRC "util/I2PEndian.cpp")
endif()

if(WITH_CRYPTOPP)
  set(CRYPTOPP_DIR "crypto/pimpl/cryptopp")
endif()

set(CRYPTO_SRC
  "${CRYPTOPP_DIR}/AES.cpp"
  "${CRYPTOPP_DIR}/CryptoConst.cpp"
  "${CRYPTOPP_DIR}/DiffieHellman.cpp"
  "${CRYPTOPP_DIR}/ElGamal.cpp"
  "${CRYPTOPP_DIR}/Hash.cpp"
  "${CRYPTOPP_DIR}/Rand.cpp"
  "${CRYPTOPP_DIR}/Signature.cpp"
  "${CRYPTOPP_DIR}/Tunnel.cpp"
  "${CRYPTOPP_DIR}/util/Checksum.cpp"
  "${CRYPTOPP_DIR}/util/Compression.cpp"
  "${CRYPTOPP_DIR}/util/X509.cpp")

if(WITH_SUPERCOP)
  set(EDDSA_DIR "crypto/pimpl/supercop")
  add_subdirectory("crypto/pimpl/supercop/ed25519")
endif()

set(EDDSA_SRC
  "${EDDSA_DIR}/Signature.cpp"
  "${EDDSA_DIR}/ed25519/fe_0.cpp"
  "${EDDSA_DIR}/ed25519/fe_1.cpp"
  "${EDDSA_DIR}/ed25519/fe_add.cpp"
  "${EDDSA_DIR}/ed25519/fe_cmov.cpp"
  "${EDDSA_DIR}/ed25519/fe_copy.cpp"
  "${EDDSA_DIR}/ed25519/fe_frombytes.cpp"
  "${EDDSA_DIR}/ed25519/fe_invert.cpp"
  "${EDDSA_DIR}/ed25519/fe_isnegative.cpp"
  "${EDDSA_DIR}/ed25519/fe_isnonzero.cpp"
  "${EDDSA_DIR}/ed25519/fe_mul.cpp"
  "${EDDSA_DIR}/ed25519/fe_neg.cpp"
  "${EDDSA_DIR}/ed25519/fe_pow22523.cpp"
  "${EDDSA_DIR}/ed25519/fe_sq.cpp"
  "${EDDSA_DIR}/ed25519/fe_sq2.cpp"
  "${EDDSA_DIR}/ed25519/fe_sub.cpp"
  "${EDDSA_DIR}/ed25519/fe_tobytes.cpp"
  "${EDDSA_DIR}/ed25519/ge_add.cpp"
  "${EDDSA_DIR}/ed25519/ge_double_scalarmult.cpp"
  "${EDDSA_DIR}/ed25519/ge_frombytes.cpp"
  "${EDDSA_DIR}/ed25519/ge_madd.cpp"
  "${EDDSA_DIR}/ed25519/ge_msub.cpp"
  "${EDDSA_DIR}/ed25519/ge_p1p1_to_p2.cpp"
  "${EDDSA_DIR}/ed25519/ge_p1p1_to_p3.cpp"
  "${EDDSA_DIR}/ed25519/ge_p2_0.cpp"
  "${EDDSA_DIR}/ed25519/ge_p2_dbl.cpp"
  "${EDDSA_DIR}/ed25519/ge_p3_0.cpp"
  "${EDDSA_DIR}/ed25519/ge_p3_dbl.cpp"
  "${EDDSA_DIR}/ed25519/ge_p3_to_cached.cpp"
  "${EDDSA_DIR}/ed25519/ge_p3_to_p2.cpp"
  "${EDDSA_DIR}/ed25519/ge_p3_tobytes.cpp"
  "${EDDSA_DIR}/ed25519/ge_precomp_0.cpp"
  "${EDDSA_DIR}/ed25519/ge_scalarmult_base.cpp"
  "${EDDSA_DIR}/ed25519/ge_sub.cpp"
  "${EDDSA_DIR}/ed25519/ge_tobytes.cpp"
  "${EDDSA_DIR}/ed25519/keypair.cpp"
  "${EDDSA_DIR}/ed25519/open.cpp"
  "${EDDSA_DIR}/ed25519/sc_muladd.cpp"
  "${EDDSA_DIR}/ed25519/sc_reduce.cpp"
  "${EDDSA_DIR}/ed25519/sign.cpp"
  "${EDDSA_DIR}/ed25519/verify.cpp")

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
