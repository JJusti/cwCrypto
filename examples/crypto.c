#include "../include/crypto/crypto.h"


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

    // AES CBC 解密
    size_t decrypted_len = base64_buffer_len;
    std::vector<char> decrypted;
    decrypted.resize(decrypted_len);
    cw_aes_cbc_decrypt(base64_buffer.data(), base64_buffer_len, key, &decrypted[0], decrypted_len);
    std::string decrypted_str(decrypted.data(), decrypted_len);

    return decrypted_str;
}

void main()
{
    // 秘钥
    char key[] = "288D447F83CE9314";
    // 秘钥
    char in[] = "{\"userId\":\"b7fec7c124e54220836a3b2cc06e35f0\"}";

    std::string base64_result = samples_aes_cbc_encrypt(in, key);
    std::string out = samples_aes_cbc_decrypt(base64_result.c_str(), key);

    if(out == in)
        printf("OK %s\r\n", base64_result.c_str());
    else
        printf("ERROR %s\r\n", base64_result.c_str());
}
