#ifndef __SM4_H__
#define __SM4_H__  1

#include "crypto/cipher/defs.h"

#include <vector>

/** SM4 加密算法
 * - 对称加密算法
 * - 密钥长度 16字节
 * - 分组长度16字节，需要填充到16字节整数倍
 * - 有CBC和ECB两种模式，CBC需要设定初始值
*/

class CWSM4
{
public:

    /** 默认构造函数
    * @note 使用默认工作模式ECB
    */
    CWSM4();

    /** 构造函数
    * @param [in] 工作模式
    */
    explicit CWSM4(MODE);

    /** 默认析构函数
    */
    ~CWSM4();

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

#endif
