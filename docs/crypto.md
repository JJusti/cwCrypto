# 加密函数库

## 基础知识

### 术语

- 对称秘钥加密
- 非对称秘钥加密/公开秘钥加密

- 分组密码
  
- 流密码

### 分组密码

### 分组密码工作模式

- 工作模式
    - ECB 电子密码本模式
    - CBC 加密分组链接模式
    - CFB 加密反馈模式
    - OFB 输出反馈模式

### 电子密码本模式(ECB, Electronic codebook)

- 需要加密的消息按照块密码的块大小被分为数个块，并对每个块进行独立加密

### 密码块链接模式(CBC, Cipher-block chaining)

- 每个明文块先与前一个密文块进行异或后，再进行加密。在这种方法中，每个密文块都依赖于它前面的所有明文块。同时，为了保证每条消息的唯一性，在第一个块中需要使用初始化向量。

### 填充密码块链接模式(PCBC，Propagating cipher-block chaining）或称为明文密码块链接（Plaintext cipher-block chaining）

### 密文反馈 (CFB, Cipher feedback)

- 类似于CBC，可以将块密码变为自同步的流密码；工作过程亦非常相似，CFB的解密过程几乎就是颠倒的CBC的加密过程

### 输出反馈 (OFB, Ootput feedback)

- 可以将块密码变成同步的流密码。它产生密钥流的块，然后将其与明文块进行异或，得到密文。与其它流密码一样，密文中一个位的翻转会使明文中同样位置的位也产生翻转。这种特性使得许多错误校正码，例如奇偶校验位，即使在加密前计算，而在加密后进行校验也可以得出正确结果

### 计数器模式 (CM, Counter mode), 也被称为ICM模式（Integer Counter Mode，整数计数模式）和SIC模式（Segmented Integer Counter）

### 对称加密

- DES
- 3DES
- AES
- Blowfish
- CAST
- IDEA
- RC2
- RC4
- RC5

### 非对称加密

- RSA
- ElGamal
- ECC

## 国标

## 哈希散列算法

- SH1
- SHA224
- SHA256
- SHA384
- SHA512
- MD5

- BASE64

## 常用算法对比

名称|秘钥长度|运算速度|安全性|资源消耗


@ref
- https://zh.wikipedia.org/wiki/分组密码工作模式

