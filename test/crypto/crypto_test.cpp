#include "crypto/crypto.h"

#include "gtest/gtest.h"

#include <openssl/opensslv.h>

#include <vector>

std::string samples_aes_cbc_encrypt(const char* in, const char* key)
{
    size_t in_size = strlen(in);

    // AES CBC 加密
    size_t buffer_size = sizeof(in) + 64;
    std::vector<char> buffer;
    if (buffer_size > 0)
    {
        buffer.resize(buffer_size);
        cw_aes_cbc_encrypt(in, in_size, key, &buffer[0], buffer_size);
    }

    // 加密结果base64
    std::string base64_str;
    if (buffer_size > 0)
    {
        size_t base64_buffer_size = buffer_size * 2;
        std::vector<char> base64_buffer;
        base64_buffer.resize(base64_buffer_size);
        cw_base64_encode(buffer.data(), buffer_size, &base64_buffer[0], &base64_buffer_size);
        base64_str.append((char*)base64_buffer.data(), base64_buffer_size);
    }
    return base64_str;
}

std::string samples_aes_cbc_decrypt(const char* base64_str, const char* key)
{
    size_t base64_buffer_len = strlen(base64_str);

    // 解码base64
    std::vector<char> base64_buffer;
    base64_buffer.resize(base64_buffer_len);

    base64_buffer.resize(base64_buffer_len);
    cw_base64_decode(base64_str, base64_buffer_len, &base64_buffer[0], &base64_buffer_len);

    size_t decrypted_len = base64_buffer_len;
    std::vector<char> decrypted;
    decrypted.resize(decrypted_len);
    cw_aes_cbc_decrypt(base64_buffer.data(), base64_buffer_len, key, &decrypted[0], decrypted_len);
    std::string decrypted_str(decrypted.data(), decrypted_len);

    return decrypted_str;
}

TEST(crypto, aesecb)
{
    {
        // 秘钥
        char key[] = "288D447F83CE9314";
        // 秘钥
        char in[] = "{\"userId\":\"b7fec7c124e54220836a3b2cc06e35f0\"}";

        std::string base64_result = samples_aes_cbc_encrypt(in, key);
        std::string out = samples_aes_cbc_decrypt(base64_result.c_str(), key);

        EXPECT_EQ(out, in);
    }

    /*
    *     passwd
    * abc ======> CQv9FDPtNEcGXbPJOD/eUA==
    */
    char buff[128] = { 0 };
    size_t buffLen = 128;
    cw_aes_ecb_encrypt("abc", strlen("abc"), "passwd", buff, buffLen);

    size_t base64_len = buffLen * 2;
    std::vector<char> base64_buffer;
    base64_buffer.resize(base64_len);
    cw_base64_encode(buff, buffLen, &base64_buffer[0], &base64_len);

    EXPECT_EQ(std::string((char*)base64_buffer.data(), base64_len), "CQv9FDPtNEcGXbPJOD/eUA==");

    char plain[1024] = { 0 };
    size_t plainLen = 1024;
    cw_aes_ecb_decrypt(buff, buffLen, "passwd", plain, plainLen);

    EXPECT_EQ(std::string((char*)plain, plainLen), "abc");

    EXPECT_EQ(0, 0);
}

TEST(crypto, aescbc)
{
    char key[] = "288D447F83CE9314";

    char buff[128] = { 0 };
    size_t buffLen = 128;
    cw_aes_cbc_encrypt("abc", strlen("abc"), key, buff, buffLen);

    size_t base64_len = buffLen * 2;
    std::vector<char> base64_buffer;
    base64_buffer.resize(base64_len);
    cw_base64_encode(buff, buffLen, &base64_buffer[0], &base64_len);

    std::string out((char*)base64_buffer.data(), base64_len);
    EXPECT_EQ(out, "KrlX9a62+aWwfvUYI/B14Q==");

    char plain[1024] = { 0 };
    size_t plainLen = 1024;
    cw_aes_cbc_decrypt((char*)buff, buffLen, key, plain, plainLen);

    EXPECT_EQ(std::string((char*)plain, plainLen), "abc");

    EXPECT_EQ(0, 0);
}
