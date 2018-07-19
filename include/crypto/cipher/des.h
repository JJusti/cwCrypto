#ifndef __DES_H__
#define __DES_H__  1

#include "Crypto/Cipher/Defs.h"

#include <string>

/** AES `(Advanced Encryption Standard)` 对称加密算法
    默认模式: ECB
*/
class DES
{
public:

    /** 默认构造函数
     * @note 使用默认工作模式ECB
    */
    DES();

    /** 构造函数
     * @param [in] 工作模式
    */
    explicit DES(MODE);

    /** 默认析构函数
    */
    ~DES();

    /** 加密字符串
     * @param [in] plainText 原始字符串
     * @param [in] key 加密秘钥
     * @param [out] cipherText 加密后字符串
    */
    bool Encrypt(const std::string& plainText, const std::string& key, std::string& cipherText);

    /** 解密字符串
     * @param [in] plainText 加密字符串
     * @param [in] key 秘钥
     * @param [out] cipherText 解密字符串
    */
    bool Decrypt(const std::string& plainText, const std::string& key, std::string& cipherText);

    /** 加密字符串
     * @param [in] m 工作模式
     * @param [in] plainText 原始字符串
     * @param [in] key 加密秘钥
     * @param [out] 加密字符串
    */
    static void Encrypt(MODE m, const std::string& plainText, const std::string& key, std::string& cipherText);

    /** 解密字符串
     * @param [in] m 工作模式
     * @param [in] cipherText 加密字符串
     * @param [in] key 加密秘钥
     * @param [out] plainText 解密后字符串
    */
    static void Decrypt(MODE m, const std::string& cipherText, const std::string& key, std::string& plainText);
};

#endif
