cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(kovri-tests CXX)

add_executable(kovri-tests 
  client/address_book/impl.cc
  client/api/i2p_control/data.cc
  client/api/i2p_control/parser.cc
  client/reseed.cc
  client/proxy/http.cc
  client/util/http.cc
  client/util/parse.cc
  client/util/zip.cc
  core/crypto/aes.cc
  core/crypto/dsa.cc
  core/crypto/eddsa25519.cc
  core/crypto/elgamal.cc
  core/crypto/radix.cc
  core/crypto/rand.cc
  core/crypto/util/x509.cc
  core/router/identity.cc
  core/router/info.cc
  core/router/transports/ssu/packet.cc
  core/util/byte_stream.cc
  core/util/config.cc
  main.cc
  core/router/identity.h)

set_property(SOURCE main.cc PROPERTY COTIRE_EXCLUDED TRUE)
set_property(SOURCE core/crypto/util/x509.cc PROPERTY COTIRE_EXCLUDED TRUE)

find_package(Boost REQUIRED COMPONENTS unit_test_framework)

target_link_libraries(kovri-tests PRIVATE 
  Boost::unit_test_framework
  kovri-private
  kovri-client)

if (COMMAND cotire)
  set_target_properties(kovri-tests PROPERTIES COTIRE_PREFIX_HEADER_INCLUDE_PATH "${CMAKE_SOURCE_DIR}/deps")
  cotire(kovri-tests)

  set(tests_target kovri-tests_unity)
else()
  set(tests_target kovri-tests)
endif()

add_test(NAME KovriTest COMMAND ${tests_target})

if (MSVC AND NOT WITH_STATIC)
  file(TO_NATIVE_PATH "${Boost_LIBRARY_DIRS}" BOOST_DLL_DIR)
  file(TO_NATIVE_PATH "${OPENSSL_ROOT_DIR}/bin" OPENSSL_DLL_DIR)
  set_property(TEST KovriTest PROPERTY ENVIRONMENT "PATH=%PATH%\;${BOOST_DLL_DIR}\;${OPENSSL_DLL_DIR}")
endif()

install(TARGETS kovri-tests RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}) 
