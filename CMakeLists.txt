####
# Set minimum version of CMake. Since command 'project' use
# VERSION sub-option we need at least 3.0.
cmake_minimum_required(VERSION 3.2 FATAL_ERROR)

include(cmake/ucm.cmake)

####
# Set variables:
#   * PROJECT_NAME
#   * PROJECT_VERSION
project(cwcrypto VERSION 0.1.0 LANGUAGES C CXX)

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

# BUILD_SHARED_LIBS is a standard CMake variable, but we declare it here to
# make it prominent in the GUI.
option(BUILD_SHARED_LIBS "Build shared libraries (DLLs)." OFF)

option(BUILD_TESTS      "Set to ON to build tests"              OFF)

MESSAGE(STSTUS "###################################")

MESSAGE(STATUS "operation system is ${CMAKE_SYSTEM}")

IF (CMAKE_SYSTEM_NAME MATCHES "Linux")
	MESSAGE(STATUS "current platform: Linux ")
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Windows")
	MESSAGE(STATUS "current platform: Windows")
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
	MESSAGE(STATUS "current platform: FreeBSD")
ELSE ()
	MESSAGE(STATUS "other platform: ${CMAKE_SYSTEM_NAME}")
ENDIF (CMAKE_SYSTEM_NAME MATCHES "Linux")

math(EXPR BITS "8*${CMAKE_SIZEOF_VOID_P}")
if (${BITS} EQUAL 32)
    set(PLATFORMTARGET "x86")
elseif (${BITS} EQUAL 64)
    set(PLATFORMTARGET "x64")
endif()
MESSAGE(STATUS "current platformtarget: ${PLATFORMTARGET}")

MESSAGE(STSTUS "###################################")

if(MSVC)
    add_compile_options(/W3 /wd4005 /wd4996 /wd4018)
    add_compile_options(/source-charset:utf-8)
    add_compile_options(-DUNICODE -D_UNICODE -D_CRT_SECURE_NO_WARNINGS)
endif()

ucm_set_runtime(STATIC)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)
SET(CMAKE_PDB_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

add_subdirectory(src)

if (BUILD_TESTS)
    add_subdirectory(test)
    add_subdirectory(vendor/googletest)
endif()
