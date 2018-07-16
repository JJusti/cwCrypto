## 摘要算法使用

摘要算法接头相同，以下以 MD5 算法为例。

### 接口设计

使用方式

  - 单独字符串/数据缓冲区计算摘要
  - 多个字符串或数据缓冲区拼接计算摘要

摘要计算结果获取

  - 获取二进制结果
  - 获取字符串形式结果(十六进制字符串)

### 类文件

```
class MD5
{
public:
    MD5();
    ~MD5();

    /** 结果大小，总是16
     * @return 返回摘要算法结果大小
    */
    static size_t digestSize();

    /** 初始化MD5计算环境
     * @note 首次准备计算MD5值或准备重新开始计算新数据MD5值调用
    */
    void Init();

    /** 计算字符串MD5值，重复调用时可以叠加不通字符串叠加计算MD5值
     * @param [in] src 
    */
    void Update(const std::string& src);

    /** 计算数据缓冲区，重复调用可以叠加不同数据缓冲区计算MD5值
     * @param [in] s 数据缓冲区地址
     * @param [in] len 数据缓冲区大小
    */
    void Update(const unsigned char* s, size_t len);

    /** 获取MD5计算结果
     * @return 返回字符串形式MD5计算结果
    */
    std::string MD5Value() const;

    /** 获取原始MD5计算结果
     * @param [in|out] 计算结果保存缓冲区地址
     * @param [in] 计算结果保存缓冲区大小
     * @return 返回二进制形式MD5计算结果
    */
    void RawMD5Value(unsigned char* buff, size_t len) const;

public:

    /** 计算字符串MD5值
     * @param [in] src 需要计算MD5值得字符串
     * @return 返回 src 对应的MD5值
    */
    static std::string Calc(const std::string& src);

    /** 计算数据缓冲区MD5值
     * @param [in] s 数据缓冲区地址
     * @param [in] len 数据缓冲区大小
     * @return 返回数据缓冲区对应的MD5值
    */
    static std::string Calc(const unsigned char* s, size_t len);
}

```

### 使用示例

```

#include "MD5.h"

#include <string>
#include <vector>

int main()
{
    std::string s("abc")
    unsigned char* buff[] = "abc";
    std::vector<unsigned char> v;
    v.push_back('a');
    v.push_back('b');
    v.push_back('c');

    // 1. 叠加计算多个字符串或内存缓冲区Hash值
    MD5 h;
    h.Init();
    h.Update(s);
    h.Update(buff, strlen(buff));
    std::string hashValue0 = h.MD5Value();      // s buff 叠加Hash值，字符串形式
    h.Init();                                   // 重新初始化计算环境
    h.Update(s);
    h.Update(buff, strlen(buff));
    h.Update(v.data(), v.size());
    std::string hashValue1 = h.MD5Value();      // s buff v 三个内存块叠加计算Hash值
    std::vector<unsigned char> digest;
    digest.resize(MD5::digestSize());           // 根据digestSize预分配存储空间
    h.RawHashValue(&digest[0], digest.size());  // 获取二进制形式摘要计算结果

    // 2. 计算确定字符串Hash值
    std::string strHashValue = MD5::Calc(s);

    // 3. 计算内存缓冲区Hash值
    std::string buffHashValue0 = MD5::Calc(buff, strlen(buff));
    std::string buffHashValue1 = MD5::Calc(v.data(), v.size());

    return 0;
}

```

## 块加密算法

### 接口设计

- 对某种加密算法可以在其支持的工作模式(ECB、CBC等)种指定工作模式
- 使用上加解密输入数据可以为字符串类型和内存缓冲区，分别提供接口方便使用

### 头文件

```
/* 分块加密算法工作模式
*/
enum MODE
{
    ECB,
    CBC,
};

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
     * @param m 工作模式
    */
    void SetMode(MODE m);

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
     * @param [in] plainText 加密字符串
     * @param [in] key 秘钥
     * @param [out] cipherText 解密字符串
    */
    bool Decrypt(const std::string& plainText, const std::string& key, std::string& cipherText);

    /** 解密内存缓冲区
     * @param [in] cipherData 密文缓冲区地址
     * @param [in] len 密文缓冲区长度
     * @param [in] key 秘钥
     * @param [out] plainData 明文数据
    */
    bool Decrypt(const unsigned char *cipherData, size_t dataLen, const std::string& key, std::vector<unsigned char>& plainData);

public:

    /** 加密字符串
     * @param [in] m 工作模式
     * @param [in] plainText 原始字符串
     * @param [in] key 加密秘钥
     * @param [out] cipherText 加密字符串
    */
    static void Encrypt(MODE m, const std::string& plainText, const std::string& key, std::string& cipherText);
    
    /** 加密内存块
     * @param [in] m 工作模式
     * @param [in] data 明文数据
     * @param [in] dataLen 明文数据长度
     * @param [in] key 加密秘钥
     * @param [out] cipherBuff 密文
    */
    static bool Encrypt(MODE m, const unsigned char *data, size_t dataLen, const std::string& key, std::vector<unsigned char>& cipherBuff);

    /** 解密字符串
     * @param [in] m 工作模式
     * @param [in] cipherText 加密字符串
     * @param [in] key 加密秘钥
     * @param [out] plainText 解密后字符串
    */
    static void Decrypt(MODE m, const std::string& cipherText, const std::string& key, std::string& plainText);

    /** 解密内存缓冲区
     * @param [in] m 工作模式
     * @param [in] cipherData 密文缓冲区地址
     * @param [in] len 密文缓冲区长度
     * @param [in] key 秘钥
     * @param [out] plainData 明文数据
    */
    static bool Decrypt(MODE m, const unsigned char *cipherData, size_t dataLen, const std::string& key, std::vector<unsigned char>& plainData);
};
```

### 使用示例

```
#include "aes.h"

#include <string>
#include <vector>

int main()
{
    std::string key("passwd");

    // 1. 使用默认模式(ECB模式)
    {
        std::string plainText("string to be encrypt");
        std::vector<unsigned char> buff(64, 3);
        std::string cipherText;

        // AES aes;                                 // 默认构造参数，使用默认工作模式ECB
        AES aes(MODE::CBC);                         // 通过构造参数指定CBC工作模式
        aes.SetMode(MODE::CBC);                     // 设置CBC模式
        aes.Encrypt(plainText, key, cipherText);    // 加密字符串
        aes.Encrypt(buff.data(), buff.size(), key, cipherText);    // 加密内存块
        std::string outText;
        aes.Decrypt(cipherText, key, outText);      // 解密后明文存储为字符串
        std::vector<unsigned char> outBuff;
        aes.Decrypt(cipherText, key, outBuff);      // 解密后明文存储到vector
    }

    // 2. 仅单次加解密时可以使用静态方法，简化使用
    {
        std::string plainText("string to be encrypt");
        std::string cipherText;
        AES::Encrypt(MODE::CBC, plainText, key, cipherText);
        std::string out;
        AES::Decrypt(MODE::CBC, cipherText, key, out);

        std::vector<unsigned char> buff(64, 3);
        std::vector<unsigned char> outBuff;
        AES::Encrypt(MODE::CBC, buff.data(), buff.size(), outBuff);
    }

    return 0;
}
```

## 流加密算法

### 头文件

```
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
```

## Base64编解码

### 接口设计

- 使用上加解密输入数据可以为字符串类型和内存缓冲区，分别提供接口方便使用
- 解码Base64时可能因为输入格式错误解码失败

### 头文件

```
class Base64
{
public:
    
    /** Base64编码字符串
     * @param [in] src 原始字符串
     * @return 返回编码后字符串
    */
    static std::string Encode(const std::string& src);

    /** Base64编码内存缓冲区
     * @param [in] src 内存缓冲区地址
     * @param [in] len 内存缓冲区长度
     * @return 返回内存缓冲区Base64编码
    */
    static std::string Encode(const unsigned char* src, size_t len);

    /** Base64解码字符串
     * @param [in] src 待解码Base64字符串
     * @param [out] out 返回解码后数据
     * @return 解码成功返回true，否则返回false
    */
    static bool Decode(const std::string& src, std::string& out);

    /** Base64解码字符串
     * @param [in] src 待解码内存缓冲区地址
     * @param [in] srcLen 待解码内存缓冲区大小
     * @param [out] out 返回解码后数据
     * @return 解码成功返回true，否则返回false
    */
    static bool Decode(const unsigned char* src, size_t srcLen, std::vector<unsigned char>& out);
}
```

### 使用示例

```
    std::string s("data to be encoded");
    std::string encoded = Base64::Endoce(s);
    std::string decoded = Base64::Decode(encoded);
```
