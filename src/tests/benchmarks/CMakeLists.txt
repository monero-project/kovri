set(BENCHMARKS_SRC
  "signature.cc")

include_directories("../../core/")

if(WITH_BENCHMARKS)
  add_executable(${BENCHMARKS_NAME} ${BENCHMARKS_SRC})
  target_link_libraries(
    ${BENCHMARKS_NAME} ${CORE_NAME}
    ${Boost_LIBRARIES} ${CryptoPP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
  install(TARGETS
    ${BENCHMARKS_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# vim: noai:ts=2:sw=2
