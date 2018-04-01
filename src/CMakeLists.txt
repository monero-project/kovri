cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(kovri-src CXX)

function(ConfigureBinary BIN_NAME OUT_NAME)
  target_link_libraries(${BIN_NAME} PRIVATE
    kovri-core
    kovri-client 
    kovri-private)
  set_target_properties(${BIN_NAME} PROPERTIES OUTPUT_NAME "${OUT_NAME}")
  if(WITH_STATIC)
    if(NOT MINGW AND NOT MSVC AND NOT APPLE)
      set_property(TARGET ${BIN_NAME} APPEND_STRING PROPERTY LINK_FLAGS " -static-libgcc -static-libstdc++")
    endif()
    if(CLANG AND NOT (ARM OR ANDROID) )
      set_property(TARGET ${BIN_NAME} APPEND_STRING PROPERTY LINK_FLAGS " -lstdc++")
      if(FREEBSD)
        set_property(TARGET ${BIN_NAME} APPEND_STRING PROPERTY LINK_FLAGS " -lm -lc++")
      endif()
    endif()
    # Note: On FreeBSD 10.3-RELEASE-p4 and 11, GCC 4.9.4+/Clang 3.6+ apparently started to *silently* drop -static-libgcc -static-libstdc++ during linkage so, we add -static here
    if(FREEBSD OR MINGW)
      set_property(TARGET ${BIN_NAME} APPEND_STRING PROPERTY LINK_FLAGS " -static")
    endif()
  endif()
  if(WITH_HARDENING AND CMAKE_CXX_COMPILER_ID STREQUAL GNU)
      set_property(TARGET ${BIN_NAME} APPEND_STRING PROPERTY LINK_FLAGS " -z relro -z now")
  endif()
endfunction()

if (WITH_LIBRARY)
  add_subdirectory(core)
  add_subdirectory(client)
endif()

if (WITH_BINARY)
  add_subdirectory(app)
  if (WITH_KOVRI_UTIL)
    add_subdirectory(util)
  endif()
endif()


