include_directories("../")

set(UTIL_SRC
  "su3file.cc"
  "routerinfo.cc"
  "base.cc"
  "benchmark.cc"
  "main.cc")

if(WITH_BINARY)
  ConfigureBinary(${UTIL_NAME} "${UTIL_SRC}" ${UTIL_NAME})
endif()

# vim: noai:ts=2:sw=2
