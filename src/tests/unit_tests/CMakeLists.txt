set(TESTS_SRC
  "Base64.cpp"
  "Crypto.cpp"
  "Identity.cpp"
  "Utility.cpp"
)

include_directories("../../" "../../core/")

if(WITH_TESTS)
    find_package(Boost COMPONENTS
        system filesystem regex program_options date_time thread chrono
        unit_test_framework REQUIRED
    )
    add_executable(${TESTS_NAME} ${TESTS_SRC})
    target_link_libraries(
		${TESTS_NAME} ${CORE_NAME} ${DL_LIB} ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
    )
    enable_testing()
    add_test(KovriTest ${TESTS_NAME})
    install(TARGETS
        ${TESTS_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

# vim: noai:ts=4:sw=4
