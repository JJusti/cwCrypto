# gtest tuple
# Summary of tuple support for Microsoft Visual Studio:
# Compiler    version(MS)  version(cmake)  Support
# ----------  -----------  --------------  -----------------------------
# <= VS 2010  <= 10        <= 1600         Use Google Tests's own tuple.
# VS 2012     11           1700            std::tr1::tuple + _VARIADIC_MAX=10
# VS 2013     12           1800            std::tr1::tuple
if (MSVC AND MSVC_VERSION EQUAL 1700)
  add_definitions(/D _VARIADIC_MAX=10)
endif()

message(STATUS $(PLATFORMTARGET))

include_directories(${PROJECT_SOURCE_DIR}/include/)
include_directories(${PROJECT_SOURCE_DIR}/vendor/googletest/include/)
#include_directories(${PROJECT_SOURCE_DIR}/vendor/openssl/${PLATFORMTARGET}/include)
include_directories(${PROJECT_SOURCE_DIR}/vendor/GmSSL/${PLATFORMTARGET}/include)

#link_directories("${PROJECT_SOURCE_DIR}/vendor/openssl/${PLATFORMTARGET}/lib")
link_directories("${PROJECT_SOURCE_DIR}/vendor/GmSSL/${PLATFORMTARGET}/lib")

set(CPP_TEST_SOURCES
  crypto/crypto_test.cpp
  crypto/encode/base64_test.cpp
  crypto/hash/md5_test.cpp
  crypto/hash/sha_test.cpp
  crypto/hash/sm3_test.cpp
)

add_executable(test ${CPP_TEST_SOURCES})

#target_link_libraries(test cwcrypto gtest gtest_main libssl libcrypto legacy_stdio_definitions)
target_link_libraries(test cwcrypto gtest gtest_main libssl libcrypto)
