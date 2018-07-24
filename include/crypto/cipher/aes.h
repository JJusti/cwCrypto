#ifndef __CRYPTO_AES_H__
#define __CRYPTO_AES_H__    1

#include "crypto/base.h"
#include "crypto/cipher/defs.h"

#include <vector>

/** AES `(Advanced Encryption Standard)` 对称加密算法
    默认模式: ECB
*/
class AES
{
public:

    /** 默认构造函数
     * @note 使用默认工作模式ECB
    */
    AES();

    /** 构造函数
     * @param [in] 工作模式
    */
    explicit AES(MODE);

    /** 默认析构函数
    */
    ~AES();

    /** 设置工作模式
     * @param mode 工作模式
    */
    void SetMode(MODE mode);

    /** 获取工作模式
     * @return 返回工作模式
    */
    MODE GetMode() const;

    /** 加密字符串
     * @param [in] plainText 原始字符串
     * @param [in] key 加密秘钥
     * @param [out] cipherText 加密后字符串
    */
    bool Encrypt(const std::string& plainText, const std::string& key, std::string& cipherText);

    /** 加密内存块
     * @param [in] data 明文数据
     * @param [in] dataLen 明文数据长度
     * @param [in] key 加密秘钥
     * @param [out] cipherBuff 密文
    */
    bool Encrypt(const unsigned char *data, size_t dataLen, const std::string& key, std::vector<unsigned char>& cipherBuff);

    /** 解密字符串
     * @param [in] cipherText 密文字符串
     * @param [in] key 秘钥
     * @param [out] plainText 明文字符串
    */
    bool Decrypt(const std::string& cipherText, const std::string& key, std::string& plainText);

    /** 解密内存缓冲区
     * @param [in] cipherData 密文缓冲区地址
     * @param [in] len 密文缓冲区长度
     * @param [in] key 秘钥
     * @param [out] plainData 明文数据
    */
    bool Decrypt(const unsigned char *cipherData, size_t dataLen, const std::string& key, std::vector<unsigned char>& plainData);

private:

    /** 工作模式
    */
    MODE mode_;
};

#endif // __CRYPTO_AES_H__
