include_directories(../../include)
include_directories(../../vendor/openssl/${PLATFORMTARGET}/include)

set(CPP_HDRS
  ../../include/crypto/base.h
  ../../include/crypto/encode/base64.h
  ../../include/crypto/hash/md5.h
  ../../include/crypto/hash/sha.h
  ../../include/crypto/hash/sha224.h
  ../../include/crypto/hash/sha256.h
  ../../include/crypto/hash/sha384.h
  ../../include/crypto/hash/sha512.h
)

set(CPP_SOURCES
  encode/base64.cpp
  hash/md5.cpp
  hash/sha.cpp
  hash/sha224.cpp
  hash/sha256.cpp
  hash/sha384.cpp
  hash/sha512.cpp
)

add_library(cwcrypto ${CPP_HDRS} ${CPP_SOURCES})

if(BUILD_SHARED_LIBS)
  target_compile_definitions(cwcrypto PRIVATE -DLIBCONFIGXX_EXPORTS)
else()
  target_compile_definitions(cwcrypto PUBLIC -DLIBCONFIGXX_STATIC)
endif()

target_link_libraries(cwcrypto)
