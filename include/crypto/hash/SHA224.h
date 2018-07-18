#ifndef __SHA224_H__
#define __SHA224_H__    1

#include <string>

class SHA224
{
public:
    SHA224();
    ~SHA224();

    /** 初始化SHA224计算环境
     * @note 首次准备计算SHA224值或准备重新开始计算新数据SHA224值调用
    */
    void Init();

    /** 计算字符串SHA224值，重复调用时可以叠加不通字符串叠加计算SHA224值
     * @param [in] src 
    */
    void Update(const std::string& src);

    /** 计算数据缓冲区，重复调用可以叠加不同数据缓冲区计算SHA224值
     * @param [in] s 数据缓冲区地址
     * @param [in] len 数据缓冲区大小
    */
    void Update(const unsigned char* s, size_t len);

    /** 获取SHA224计算结果
     * @return 返回字符串形式SHA224计算结果
    */
    std::string SHA224Value() const;

    /** 获取原始SHA224计算结果
     * @param [in|out] 计算结果保存缓冲区地址
     * @param [in] 计算结果保存缓冲区大小
     * @return 返回二进制形式SHA224计算结果
    */
    void RawSHA224Value(unsigned char* buff, size_t len) const;

    /** 计算字符串SHA224值
     * @param [in] src 需要计算SHA224值得字符串
     * @return 返回 src 对应的SHA224值
    */
    static std::string Calc(const std::string& src);

    /** 计算数据缓冲区SHA224值
     * @param [in] s 数据缓冲区地址
     * @param [in] len 数据缓冲区大小
     * @return 返回数据缓冲区对应的SHA224值
    */
    static std::string Calc(const unsigned char* s, size_t len);
}

#endif
