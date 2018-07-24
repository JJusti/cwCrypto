#ifndef __SM2_H__
#define __SM2_H__  1

#include "crypto/base.h"

/** SM2 加密算法
 * - 非对称加密算法
 * - 公钥64字节，私钥32字节
 * - 输入数据长度小于 (2^32-1)字节
 * - 输出数据长度为 明文长度+96
 * - 有随机参数，每次密文不同
*/

class CWSM2
{
public:
    CWSM2();
    ~CWSM2();

private:

};

#endif
