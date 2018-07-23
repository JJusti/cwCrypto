include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/vendor/openssl/${PLATFORMTARGET}/include)
include_directories(${PROJECT_SOURCE_DIR}/vendor/GmSSL/${PLATFORMTARGET}/include)

link_directories("${PROJECT_SOURCE_DIR}/vendor/openssl/${PLATFORMTARGET}/lib")
link_directories("${PROJECT_SOURCE_DIR}/vendor/GmSSL/${PLATFORMTARGET}/lib")

set(CPP_HDRS
  ${PROJECT_SOURCE_DIR}/include/crypto/base.h
  ${PROJECT_SOURCE_DIR}/include/crypto/crypto.h
  ${PROJECT_SOURCE_DIR}/include/crypto/cipher/aes.h
  ${PROJECT_SOURCE_DIR}/include/crypto/cipher/rc4.h
  ${PROJECT_SOURCE_DIR}/include/crypto/cipher/rsa.h
  ${PROJECT_SOURCE_DIR}/include/crypto/cipher/sm2.h
  ${PROJECT_SOURCE_DIR}/include/crypto/cipher/sm4.h
  ${PROJECT_SOURCE_DIR}/include/crypto/encode/base64.h
  ${PROJECT_SOURCE_DIR}/include/crypto/hash/md5.h
  ${PROJECT_SOURCE_DIR}/include/crypto/hash/sha.h
  ${PROJECT_SOURCE_DIR}/include/crypto/hash/sha224.h
  ${PROJECT_SOURCE_DIR}/include/crypto/hash/sha256.h
  ${PROJECT_SOURCE_DIR}/include/crypto/hash/sha384.h
  ${PROJECT_SOURCE_DIR}/include/crypto/hash/sha512.h
  ${PROJECT_SOURCE_DIR}/include/crypto/hash/sm3.h
)

set(CPP_SOURCES
  crypto.cpp
  cipher/aes.cpp
  cipher/rc4.cpp
  cipher/rsa.cpp
  encode/base64.cpp
  hash/md5.cpp
  hash/sha.cpp
  hash/sha224.cpp
  hash/sha256.cpp
  hash/sha384.cpp
  hash/sha512.cpp
  hash/sm3.cpp
)

add_library(cwcrypto ${CPP_HDRS} ${CPP_SOURCES})

target_link_libraries(cwcrypto libeay32 ssleay32 libssl libcrypto)
