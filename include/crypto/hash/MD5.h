#ifndef __HASH_MD5_H__
#define __HASH_MD5_H__   1

#include <string>

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

#endif // __HASH_MD5_H__
