set(TESTS_SRC
  "Main.cpp"
  "core/Reseed.cpp"
  "core/Identity.cpp"
  "core/transport/SSUPacket.cpp"
  "core/crypto/AES.cpp"
  "core/crypto/DSA.cpp"
  "core/crypto/EdDSA25519.cpp"
  "core/crypto/ElGamal.cpp"
  "core/crypto/Rand.cpp"
  "core/crypto/util/X509.cpp"
  "core/util/Base64.cpp"
  "core/util/HTTP.cpp"
  "core/util/ZIP.cpp")

include_directories(
  "../../"
  "../../app/"
  "../../core/"
  "../../client/")

if(WITH_TESTS)
  find_package(
    Boost COMPONENTS
    unit_test_framework
    chrono program_options
    date_time thread system
    filesystem regex
    REQUIRED)
  add_executable(${TESTS_NAME} ${TESTS_SRC})
  target_link_libraries(
    ${TESTS_NAME} ${CORE_NAME} ${CLIENT_NAME}
    ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
  enable_testing()
  add_test(KovriTest ${TESTS_NAME})
  install(TARGETS
    ${TESTS_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# vim: noai:ts=2:sw=2
