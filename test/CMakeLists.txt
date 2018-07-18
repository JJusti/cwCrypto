INCLUDE_DIRECTORIES(../include/)
INCLUDE_DIRECTORIES(../vendor/googletest/include/)

set(CPP_TEST_SOURCES
  crypto/encode/base64_test.cpp
)

add_executable(cwfl_test ${CPP_TEST_SOURCES})

target_link_libraries(cwfl_test libcrypto gtest gtest_main)
