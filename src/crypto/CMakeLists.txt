
include_directories(../../include)

set(CPP_HDRS
  ../../include/crypto/encode/base64.h
)

set(CPP_SOURCES
  encode/base64.cpp
)

set(CPP_TEST_SOURCES
  encode/base64_test.cpp
)

add_library(libcrypto ${CPP_HDRS} ${CPP_SOURCES})

if(BUILD_SHARED_LIBS)
  target_compile_definitions(libcrypto PRIVATE -DLIBCONFIGXX_EXPORTS)
else()
  target_compile_definitions(libcrypto PUBLIC -DLIBCONFIGXX_STATIC)
endif()

target_link_libraries(libcrypto)
