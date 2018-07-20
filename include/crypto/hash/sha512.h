#ifndef __SHA512_H__
#define __SHA512_H__    1

#include "crypto/base.h"

class SHA512
{
public:
    SHA512();
    ~SHA512();

    /** 结果大小
     * @return 返回摘要算法结果大小
    */
    static size_t digestLength();

    /** 初始化SHA512计算环境
     * @note 首次准备计算SHA512值或准备重新开始计算新数据SHA512值调用
    */
    void Init();

    /** 计算字符串SHA512值，重复调用时可以叠加不通字符串叠加计算SHA512值
     * @param [in] src 
    */
    void Update(const std::string& src);

    /** 计算数据缓冲区，重复调用可以叠加不同数据缓冲区计算SHA512值
     * @param [in] s 数据缓冲区地址
     * @param [in] len 数据缓冲区大小
    */
    void Update(const unsigned char* s, size_t len);

    /** 获取SHA512计算结果
     * @return 返回字符串形式SHA512计算结果
    */
    std::string Value() const;

    /** 获取原始SHA512计算结果
     * @param [in|out] 计算结果保存缓冲区地址
     * @param [in] 计算结果保存缓冲区大小
     * @return 返回二进制形式SHA512计算结果
    */
    void RawValue(unsigned char* buff, size_t len) const;

public:

    /** 计算字符串SHA512值
     * @param [in] src 需要计算SHA512值得字符串
     * @return 返回 src 对应的SHA512值
    */
    static std::string Calc(const std::string& src);

    /** 计算数据缓冲区SHA512值
     * @param [in] s 数据缓冲区地址
     * @param [in] len 数据缓冲区大小
     * @return 返回数据缓冲区对应的SHA512值
    */
    static std::string Calc(const unsigned char* s, size_t len);

private:
    struct IMPL;
    std::unique_ptr<IMPL> impl_;
};

#endif // __SHA512_H__
