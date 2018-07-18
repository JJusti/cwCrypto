####
# Set minimum version of CMake. Since command 'project' use
# VERSION sub-option we need at least 3.0.
# Note: If you use 2.6 or 2.4, God kills a kitten. Seriously.
cmake_minimum_required(VERSION 3.2 FATAL_ERROR)

####
# Set variables:
#   * PROJECT_NAME
#   * PROJECT_VERSION
project(cwfl VERSION 0.1.0 LANGUAGES C CXX)

#####
# Enables link_directories() treat paths relative
# to the source dir.
if(POLICY CMP0015)
    cmake_policy(SET CMP0015 NEW)
endif(POLICY CMP0015)

#####
# Enables project() command manages VERSION variables.
if(POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif(POLICY CMP0048)

option(BUILD_TESTS      "Set to ON to build tests"              OFF)

if(MSVC)
  add_compile_options(/W3 /wd4005 /wd4996 /wd4018 -D_CRT_SECURE_NO_WARNINGS)
endif()

add_subdirectory(include)
add_subdirectory(src)

if(BUILD_TESTS)
    add_subdirectory(vendor/googletest)
    add_subdirectory(test)
endif(BUILD_TESTS)
