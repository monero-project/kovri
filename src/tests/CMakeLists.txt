if(WITH_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()

if(WITH_TESTS)
  add_subdirectory(unit_tests)
endif()

# vim: noai:ts=2:sw=2
