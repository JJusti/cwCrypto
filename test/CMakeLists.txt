# Summary of tuple support for Microsoft Visual Studio:
# Compiler    version(MS)  version(cmake)  Support
# ----------  -----------  --------------  -----------------------------
# <= VS 2010  <= 10        <= 1600         Use Google Tests's own tuple.
# VS 2012     11           1700            std::tr1::tuple + _VARIADIC_MAX=10
# VS 2013     12           1800            std::tr1::tuple
if (MSVC AND MSVC_VERSION EQUAL 1700)
  add_definitions(/D _VARIADIC_MAX=10)
endif()

INCLUDE_DIRECTORIES(../include/)
INCLUDE_DIRECTORIES(../vendor/googletest/include/)

set(CPP_TEST_SOURCES
  crypto/encode/base64_test.cpp
)

add_executable(cwfl_test ${CPP_TEST_SOURCES})

target_link_libraries(cwfl_test cwcrypto gtest gtest_main)
