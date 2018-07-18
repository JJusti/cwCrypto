#ifndef __CIPHER_RC4_H__
#define __CIPHER_RC4_H__    1

#include <stdint.h>

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
    @param [in] key 密钥数据缓冲区
    @param [in] keyLen 密钥数据长度
    */
    void SetKey(const unsigned char* key, uint32_t keyLen);

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
}

#endif // __CIPHER_RC4_H__
