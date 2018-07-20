include_directories(../../include)
include_directories(../../vendor/openssl/${PLATFORMTARGET}/include)

link_directories("../../vendor/openssl/${PLATFORMTARGET}/lib")

set(CPP_HDRS
  ../../include/crypto/base.h
  ../../include/crypto/crypto.h
  ../../include/crypto/cipher/rc4.h
  ../../include/crypto/cipher/rsa.h
  ../../include/crypto/encode/base64.h
  ../../include/crypto/hash/md5.h
  ../../include/crypto/hash/sha.h
  ../../include/crypto/hash/sha224.h
  ../../include/crypto/hash/sha256.h
  ../../include/crypto/hash/sha384.h
  ../../include/crypto/hash/sha512.h
  ../../include/crypto/hash/sm3.h
)

set(CPP_SOURCES
  crypto.cpp
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



target_link_libraries(cwcrypto libeay32 ssleay32)
