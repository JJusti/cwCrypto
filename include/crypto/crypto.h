#ifndef __CRYPTO_H__
#define __CRYPTO_H__    1

#include <stdlib.h>
#include <stdint.h>

#ifdef  __cplusplus
#define EXTERN_C  extern "C"
#endif

#ifdef CWCRYPTO_EXPORTS
#define CWCRYPTO_API    EXTERN_C __declspec(dllexport)
#else
#define CWCRYPTO_API    EXTERN_C
#endif // CWCRYPTO_EXPORTS

#define CWCRYPTO_OK                         (0)
#define CWCRYPTO_ERROR_INVALID_PARAMS       (1)
#define CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY    (2)
#define CWCRYPTO_ERROR_INVALID_KEY          (3)

/* 支持算法列表
AES
RSA1024
RSA2048
SM2
- SM4

- MD5
- SHA256
- SM3

- BASE64

*/

/** AES ECB 加密
* @param [in] plain_data 明文数据缓冲区
* @param [in] plain_length 明文数据缓冲区大小
* @param [in] key 密钥，以 '\0' 结尾字符串
* @param [out] digest_data 密文保存数据缓冲区
* @param [in][out] digest_length 输入密文保存数据缓冲区大小，执行成功时返回加密数据长度
* @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_aes_ecb_encrypt(const char* plain_data,
    size_t plain_length,
    const char* key,
    char* cipher_data,
    size_t& cipher_length);

/** AES ECB 解密
* @param [in] cipher_data 密文数据缓冲区
* @param [in] cipher_length 密文数据缓冲区大小
* @param [in] key 密钥，以 '\0' 结尾字符串
* @param [out] plain_data 明文保存数据缓冲区
* @param [in][out] plain_length 明文保存数据缓冲区大小，执行成功时返回解密明文数据长度
* @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_aes_ecb_decrypt(const char* cipher_data,
    size_t cipher_length,
    const char* key,
    char* plain_data,
    size_t& plain_length);

/** AES CBC 加密
* @param [in] plain_data 明文数据缓冲区
* @param [in] plain_length 明文数据缓冲区大小
* @param [in] key 密钥，以 '\0' 结尾字符串
* @param [out] digest_data 密文保存数据缓冲区
* @param [in][out] digest_length 输入密文保存数据缓冲区大小，执行成功时返回加密数据大小
* @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_aes_cbc_encrypt(const char* plain_data,
    size_t plain_length,
    const char* key,
    char* cipher_data,
    size_t& cipher_length);

/** AES CBC 解密
* @param [in] cipher_data 密文数据缓冲区
* @param [in] cipher_length 密文数据缓冲区大小
* @param [in] key 密钥，以 '\0' 结尾字符串
* @param [out] plain_data 明文保存数据缓冲区
* @param [in][out] plain_length 明文保存数据缓冲区大小，执行成功时返回解密明文数据长度
* @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_aes_cbc_decrypt(const char* cipher_data,
    size_t cipher_length,
    const char* key,
    char* plain_data,
    size_t& plain_length);

/** AES ECB 加密
* @param [in] plain_data 明文数据缓冲区
* @param [in] plain_length 明文数据缓冲区大小
* @param [in] key 密钥，以 '\0' 结尾字符串
* @param [out] digest_data 密文保存数据缓冲区
* @param [in][out] digest_length 输入密文保存数据缓冲区大小，执行成功时返回加密数据长度
* @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_aes_ecb_encrypt(const char* plain_data,
    size_t plain_length,
    const char* key,
    char* cipher_data,
    size_t& cipher_length);

/** SM4 ECB 解密
* @param [in] cipher_data 密文数据缓冲区
* @param [in] cipher_length 密文数据缓冲区大小
* @param [in] key 密钥，以 '\0' 结尾字符串
* @param [out] plain_data 明文保存数据缓冲区
* @param [in][out] plain_length 明文保存数据缓冲区大小，执行成功时返回解密明文数据长度
* @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_sm4_ecb_decrypt(const char* cipher_data,
    size_t cipher_length,
    const char* key,
    char* plain_data,
    size_t& plain_length);

/** SM4 CBC 加密
* @param [in] plain_data 明文数据缓冲区
* @param [in] plain_length 明文数据缓冲区大小
* @param [in] key 密钥，以 '\0' 结尾字符串
* @param [out] digest_data 密文保存数据缓冲区
* @param [in][out] digest_length 输入密文保存数据缓冲区大小，执行成功时返回加密数据大小
* @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_sm4_cbc_encrypt(const char* plain_data,
    size_t plain_length,
    const char* key,
    char* cipher_data,
    size_t& cipher_length);

/** SM4 CBC 解密
* @param [in] cipher_data 密文数据缓冲区
* @param [in] cipher_length 密文数据缓冲区大小
* @param [in] key 密钥，以 '\0' 结尾字符串
* @param [out] plain_data 明文保存数据缓冲区
* @param [in][out] plain_length 明文保存数据缓冲区大小，执行成功时返回解密明文数据长度
* @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_sm4_cbc_decrypt(const char* cipher_data,
    size_t cipher_length,
    const char* key,
    char* plain_data,
    size_t& plain_length);

CWCRYPTO_API int cw_rsa_load_public_key(const char* path, char* buff);
CWCRYPTO_API int cw_rsa_load_private_key(const char* path, char* buff);

CWCRYPTO_API int cw_rsa_public_encrypt(const char* plain_data,
    size_t plain_length,
    const char* public_key,
    char* cipher_data,
    size_t& cipher_length);

CWCRYPTO_API int cw_rsa_public_decrypt(const char* cipher_data,
    size_t cipher_length,
    const char* private_key,
    char* plain_data,
    size_t& plain_length);

CWCRYPTO_API int cw_rsa_private_encrypt(const char* plain_data,
    size_t plain_length,
    const char* public_key,
    char* cipher_data,
    size_t& cipher_length);

CWCRYPTO_API int cw_rsa_private_decrypt(const char* cipher_data,
    size_t cipher_length,
    const char* private_key,
    char* plain_data,
    size_t& plain_length);

/** 获取 md5 结果大小
 * @return 返回name对应摘要算法结果大小
*/
CWCRYPTO_API int cw_md5_digest_length(const char* name);

/** md5 算法
 * @param [in] plain_data 原始数据地址
 * @param [in] plain_length 原始数据大小
 * @param [out] digest_data 摘要计算结果缓冲区地址，需要保护额外 1 个字节存放字符传结束符
 * @param [in] digest_length 摘要缓冲区大小
 * @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_md5(const char* plain_data, size_t plain_length, char* digest_data, size_t digest_length);

/** 获取 sha256 结果大小
 * @return 返回name对应摘要算法结果大小
*/
CWCRYPTO_API int cw_sha256_digest_length(const char* name);

/** sha256 算法
 * @param [in] plain_data 原始数据地址
 * @param [in] plain_length 原始数据大小
 * @param [out] digest_data 摘要计算结果缓冲区地址，需要保护额外 1 个字节存放字符传结束符
 * @param [in] digest_length 摘要缓冲区大小
 * @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_sha256(const char* plain_data, size_t plain_length, char* digest_data, size_t digest_length);

/** 获取 sm3 结果大小
 * @return 返回name对应摘要算法结果大小
*/
CWCRYPTO_API int cw_sm3_digest_length(const char* name);

/** sm3 算法
 * @param [in] plain_data 原始数据地址
 * @param [in] plain_length 原始数据大小
 * @param [out] digest_data 摘要计算结果缓冲区地址，需要保护额外 1 个字节存放字符传结束符
 * @param [in] digest_length 摘要缓冲区大小
 * @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_sm3(const char* plain_data, size_t plain_length, char* digest_data, size_t digest_length);

/** Base64 编码
 * @param [in] plain_data 待编码数据地址
 * @param [in] plain_length 待编码数据大小
 * @param [out] encoded_data 编码数据保存缓冲区地址，需要保护额外 1 个字节存放字符传结束符
 * @param [in][out] encoded_length 输入编码数据保存缓冲区大小，输出编码数据大小
 * @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_base64_encode(const char *plain_data, size_t plain_length, char *encoded_data, size_t *encoded_length);

/** Base64 解码
 * @param [in] encoded_data Base64编码字符串地址
 * @param [in] encoded_length Base64编码字符串大小
 * @param [out] decoded_data 解码数据保存缓冲区地址
 * @param [out] decoded_length 输入解码数据保存缓冲区大小，数据解码数据大小
 * @return 执行正常返回0，否则返回状态码
*/
CWCRYPTO_API int cw_base64_decode(const char *encoded_data, size_t encoded_length, char *decoded_data, size_t* decoded_length);

#endif // __CRYPTO_H__
