
include_directories(../../include)

set(CPP_HDRS
  ../../include/crypto/base.h
  ../../include/crypto/encode/base64.h
)

set(CPP_SOURCES
  encode/base64.cpp
)

set(CPP_TEST_SOURCES
  encode/base64_test.cpp
)

add_library(cwcrypto ${CPP_HDRS} ${CPP_SOURCES})

if(BUILD_SHARED_LIBS)
  target_compile_definitions(cwcrypto PRIVATE -DLIBCONFIGXX_EXPORTS)
else()
  target_compile_definitions(cwcrypto PUBLIC -DLIBCONFIGXX_STATIC)
endif()

target_link_libraries(cwcrypto)
