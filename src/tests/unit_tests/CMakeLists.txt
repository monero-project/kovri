set(TESTS_SRC
  "Main.cc"
  "core/Reseed.cc"
  "core/crypto/AES.cc"
  "core/crypto/DSA.cc"
  "core/crypto/EdDSA25519.cc"
  "core/crypto/ElGamal.cc"
  "core/crypto/Rand.cc"
  "core/crypto/util/X509.cc"
  "core/util/Base64.cc"
  "core/util/HTTP.cc"
  "core/util/ZIP.cc")

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
    ${Boost_LIBRARIES} ${CryptoPP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
  enable_testing()
  add_test(KovriTest ${TESTS_NAME})
  install(TARGETS
    ${TESTS_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# vim: noai:ts=2:sw=2
