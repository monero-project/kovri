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
  core/router/transports/ssu/packet.cc
  core/util/byte_stream.cc
  main.cc)


find_package(Boost REQUIRED COMPONENTS unit_test_framework)

target_link_libraries(kovri-tests PRIVATE 
  Boost::unit_test_framework
  kovri-client
  kovri-private)

install(TARGETS kovri-tests RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}) 

add_test(NAME KovriTest COMMAND kovri-tests)
