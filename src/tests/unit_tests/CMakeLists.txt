set(TESTS_SRC
  "Base64.cpp"
  "Identity.cpp"
  "Utility.cpp"
  "crypto/aes.cpp"
  "crypto/dsa.cpp"
  "crypto/ed25519.cpp"
  "crypto/elg.cpp")

include_directories(
  "../../"
  "../../core/"
  "../../client/")

if(WITH_TESTS)
  find_package(
    Boost COMPONENTS
    chrono unit_test_framework
    program_options date_time thread
    system filesystem regex
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
