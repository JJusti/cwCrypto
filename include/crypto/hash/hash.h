#ifndef __HASH_H__
#define __HASH_H__  1

#include <string>

/** 摘要算法
 * 使用:
 *   std::string s("string type");
 *   unsigned char* b[] = "data buff";
 *   Hash h;
 *   h.Init();
 *   h.Update(s);
 *   h.Update(b, strlen(b));
 *   
 *   std::string o = h.Digest();
 * 
 *   std::string v = Hash::Calc(s);
*/

class Hash
{
public:
    Hash();
    virtual~Hash();

    /** 结果大小
     * @return 返回摘要算法结果大小
    */
    static size_t digestSize();

    /** 初始化hash计算环境
     * @note 首次准备计算hash值或准备重新开始计算新数据hash值调用
    */
    void Init();

    /** 计算字符串hash值，重复调用时可以叠加不通字符串叠加计算hash值
     * @param [in] src 
    */
    void Update(const std::string& src);

    /** 计算数据缓冲区，重复调用可以叠加不同数据缓冲区计算hash值
     * @param [in] s 数据缓冲区地址
     * @param [in] len 数据缓冲区大小
    */
    void Update(const unsigned char* s, size_t len);

    /** 获取hash计算结果
     * @return 返回字符串形式hash计算结果
    */
    std::string HashValue() const;

    /** 获取原始hash计算结果
     * @param [in|out] 计算结果保存缓冲区地址
     * @param [in] 计算结果保存缓冲区大小
     * @return 返回二进制形式hash计算结果
    */
    void RawHashValue(unsigned char* buff, size_t len) const;

    /** 计算字符串hash值
     * @param [in] src 需要计算hash值得字符串
     * @return 返回 src 对应的字符串hash值
    */
    static std::string Calc(const std::string& src);

    /** 计算数据缓冲区hash值
     * @param [in] s 数据缓冲区地址
     * @param [in] len 数据缓冲区大小
     * @return 返回数据缓冲区对应字符串hash值
    */
    static std::string Calc(const unsigned char* s, size_t len);
}

#endif
