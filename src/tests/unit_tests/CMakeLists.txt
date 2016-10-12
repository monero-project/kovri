set(TESTS_CLIENT
  "client/reseed.cc"
  "client/util/http.cc"
  "client/util/zip.cc")

set(TESTS_CORE
  "core/crypto/aes.cc"
  "core/crypto/dsa.cc"
  "core/crypto/eddsa25519.cc"
  "core/crypto/elgamal.cc"
  "core/crypto/rand.cc"
  "core/crypto/util/x509.cc"
  "core/transport/ssu_packet.cc"
  "core/util/base64.cc")

set(TESTS_MAIN
  ${TESTS_CLIENT}
  ${TESTS_CORE}
  "main.cc")

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
  add_executable(${TESTS_NAME} ${TESTS_MAIN})
  target_link_libraries(
    ${TESTS_NAME} ${CORE_NAME} ${CLIENT_NAME}
    ${Boost_LIBRARIES} ${CryptoPP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
  enable_testing()
  add_test(KovriTest ${TESTS_NAME})
  install(TARGETS
    ${TESTS_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
