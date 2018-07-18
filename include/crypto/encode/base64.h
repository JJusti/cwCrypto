#ifndef __ENCODE_BASE64_H__
#define __ENCODE_BASE64_H__    1

#include "crypto/base.h"

#include <string>
#include <vector>

namespace cwfl { namespace crypto {

/** Base64编码和解码
 * 使用示例:
 *   std::string s("data to be encoded");
 *   std::string encoded = Base64::Endoce(s);
 *   std::string decoded = Base64::Decode(encoded);
*/
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
};

}}

#endif // __ENCODE_BASE64_H__
