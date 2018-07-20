#ifndef __SM4_H__
#define __SM4_H__  1

/** SM4 加密算法
 * - 对称加密算法
 * - 密钥长度 16字节
 * - 分组长度16字节，需要填充到16字节整数倍
 * - 有CBC和ECB两种模式，CBC需要设定初始值
*/

class SM4
{
public:
    SM4();
    ~SM4();
}

#endif
