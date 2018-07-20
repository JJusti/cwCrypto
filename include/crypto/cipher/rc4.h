#ifndef __CIPHER_RC4_H__
#define __CIPHER_RC4_H__    1

#include "crypto/base.h"

/** RC4加密算法
 * - 对称加密
 * - 流加密算法，依次对每个字节加/解密
 * - 运算速度快，代码简单，秘钥长度可变，足够复杂、长度下加密效果足够强
*/
class RC4
{
public:
    /** 构造函数
    */
    RC4();
    
    /** 析构函数
    */
    ~RC4();

    /** 设置加密或者解密的Key数据, 并初始化状态
    @param [in] key 密钥
    */
    void SetKey(const std::string& key);

    /** 加密数据（每次开始数据流开始时， 都需要调用SetKeyData设置密钥）
    @param [in,out] data 输入待加密的数据, 返回加密后的数据
    @param [in] dataLen 数据长度
    */
    void Encrypt(unsigned char* data, uint32_t dataLen);

    /** 解密数据（每次开始数据流开始时， 都需要调用SetKeyData设置密钥）
    @param [in,out] data 输入待解密的数据, 返回解密后的数据
    @param [in] dataLen 数据长度
    */
    void Decrypt(unsigned char* data, uint32_t dataLen);

public:

    static std::string Encrypt(const std::string &clearText, const std::string &key);
	
    static std::string Decrypt(const std::string &cipherText, const std::string &key);

private:
    struct IMPL;
    std::unique_ptr<IMPL> impl_;
};

#endif // __CIPHER_RC4_H__
