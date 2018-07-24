#include "crypto/crypto.h"

#include "crypto/cipher/aes.h"
#include "crypto/cipher/sm4.h"

#include "crypto/hash/md5.h"
#include "crypto/hash/sha256.h"
#include "crypto/hash/sm3.h"

#include "crypto/encode/base64.h"

CWCRYPTO_API int cw_aes_ecb_encrypt(const char* plain_data,
    size_t plain_length,
    const char* key,
    char* cipher_data,
    size_t& cipher_length)
{
    if ((plain_data == NULL) || (plain_length <= 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((cipher_data == NULL) || (cipher_length <= 0))
        return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;
    if (key == NULL)
        return CWCRYPTO_ERROR_INVALID_KEY;

    std::string src;
    src.append((const char*)plain_data, plain_length);

    std::string ret;
    AES aes(MODE::ECB);
    if (!aes.Encrypt(src, std::string((const char*)key), ret))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if (ret.empty() || (ret.length() > cipher_length))
        return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;
    else
    {
        memset(cipher_data, 0, cipher_length * sizeof(char));
        memcpy(cipher_data, ret.c_str(), ret.length());

        cipher_length = ret.length();
    }
    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_aes_ecb_decrypt(const char* cipher_data,
    size_t cipher_length,
    const char* key,
    char* plain_data,
    size_t& plain_length)
{
    if ((plain_data == NULL) || (plain_length <= 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((cipher_data == NULL) || (cipher_length <= 0))
        return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;
    if (key == NULL)
        return CWCRYPTO_ERROR_INVALID_KEY;

    std::string src;
    src.append((const char*)cipher_data, cipher_length);

    std::string ret;
    AES aes(MODE::ECB);
    if (!aes.Decrypt(src, std::string((const char*)key), ret))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if (ret.empty() || (ret.length() > cipher_length))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    else
    {
        memset(plain_data, 0, plain_length * sizeof(char));
        memcpy(plain_data, ret.c_str(), ret.length());

        plain_length = ret.length();
    }
    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_aes_cbc_encrypt(const char* plain_data,
    size_t plain_length,
    const char* key,
    char* cipher_data,
    size_t& cipher_length)
{
    if ((plain_data == NULL) || (plain_length <= 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((cipher_data == NULL) || (cipher_length <= 0))
        return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;
    if (key == NULL)
        return CWCRYPTO_ERROR_INVALID_KEY;

    std::string src;
    src.append((const char*)plain_data, plain_length);

    std::string ret;
    AES aes(MODE::CBC);
    if (!aes.Encrypt(src, std::string((const char*)key), ret))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if (ret.empty() || (ret.length() > cipher_length))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    else
    {
        memset(cipher_data, 0, cipher_length * sizeof(char));
        memcpy(cipher_data, ret.c_str(), ret.length());

        cipher_length = ret.length();
    }
    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_aes_cbc_decrypt(const char* cipher_data,
    size_t cipher_length,
    const char* key,
    char* plain_data,
    size_t& plain_length)
{
    if ((plain_data == NULL) || (plain_length <= 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((cipher_data == NULL) || (cipher_length <= 0))
        return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;
    if (key == NULL)
        return CWCRYPTO_ERROR_INVALID_KEY;

    std::string src;
    src.append((const char*)cipher_data, cipher_length);

    std::string ret;
    AES aes(MODE::CBC);
    if (!aes.Decrypt(src, std::string((const char*)key), ret))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if (ret.empty() || (ret.length() > cipher_length))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    else
    {
        memset(plain_data, 0, plain_length * sizeof(char));
        memcpy(plain_data, ret.c_str(), ret.length());

        plain_length = ret.length();
    }
    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_sm4_ecb_encrypt(const char* plain_data,
    size_t plain_length,
    const char* key,
    char* cipher_data,
    size_t& cipher_length)
{
    if ((plain_data == NULL) || (plain_length <= 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((cipher_data == NULL) || (cipher_length <= 0))
        return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;
    if (key == NULL)
        return CWCRYPTO_ERROR_INVALID_KEY;

    std::string src;
    src.append((const char*)plain_data, plain_length);

    std::string ret;
    CWSM4 sm4(MODE::ECB);
    if (!sm4.Encrypt(src, std::string((const char*)key), ret))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if (ret.empty() || (ret.length() > cipher_length))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    else
    {
        memset(cipher_data, 0, cipher_length * sizeof(char));
        memcpy(cipher_data, ret.c_str(), ret.length());

        cipher_length = ret.length();
    }
    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_sm4_ecb_decrypt(const char* cipher_data,
    size_t cipher_length,
    const char* key,
    char* plain_data,
    size_t& plain_length)
{
    if ((plain_data == NULL) || (plain_length <= 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((cipher_data == NULL) || (cipher_length <= 0))
        return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;
    if (key == NULL)
        return CWCRYPTO_ERROR_INVALID_KEY;

    std::string src;
    src.append((const char*)cipher_data, cipher_length);

    std::string ret;
    CWSM4 sm4(MODE::ECB);
    if (!sm4.Decrypt(src, std::string((const char*)key), ret))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if (ret.empty() || (ret.length() > cipher_length))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    else
    {
        memset(plain_data, 0, plain_length * sizeof(char));
        memcpy(plain_data, ret.c_str(), ret.length());

        plain_length = ret.length();
    }
    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_sm4_cbc_encrypt(const char* plain_data,
    size_t plain_length,
    const char* key,
    char* cipher_data,
    size_t& cipher_length)
{
    if ((plain_data == NULL) || (plain_length <= 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((cipher_data == NULL) || (cipher_length <= 0))
        return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;
    if (key == NULL)
        return CWCRYPTO_ERROR_INVALID_KEY;

    std::string src;
    src.append((const char*)plain_data, plain_length);

    std::string ret;
    CWSM4 sm4(MODE::CBC);
    if (!sm4.Encrypt(src, std::string((const char*)key), ret))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if (ret.empty() || (ret.length() > cipher_length))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    else
    {
        memset(cipher_data, 0, cipher_length * sizeof(char));
        memcpy(cipher_data, ret.c_str(), ret.length());

        cipher_length = ret.length();
    }
    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_sm4_cbc_decrypt(const char* cipher_data,
    size_t cipher_length,
    const char* key,
    char* plain_data,
    size_t& plain_length)
{
    if ((plain_data == NULL) || (plain_length <= 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((cipher_data == NULL) || (cipher_length <= 0))
        return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;
    if (key == NULL)
        return CWCRYPTO_ERROR_INVALID_KEY;

    std::string src;
    src.append((const char*)cipher_data, cipher_length);

    std::string ret;
    CWSM4 sm4(MODE::CBC);
    if (!sm4.Decrypt(src, std::string((const char*)key), ret))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if (ret.empty() || (ret.length() > cipher_length))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    else
    {
        memset(plain_data, 0, plain_length * sizeof(char));
        memcpy(plain_data, ret.c_str(), ret.length());

        plain_length = ret.length();
    }
    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_rsa_public_encrypt(const char* plain_data,
    size_t plain_length,
    const char* public_key,
    char* cipher_data,
    size_t& cipher_length)
{
    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_rsa_public_decrypt(const char* cipher_data,
    size_t cipher_length,
    const char* private_key,
    char* plain_data,
    size_t& plain_length)
{
    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_rsa_private_encrypt(const char* plain_data,
    size_t plain_length,
    const char* public_key,
    char* cipher_data,
    size_t& cipher_length)
{
    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_rsa_private_decrypt(const char* cipher_data,
    size_t cipher_length,
    const char* private_key,
    char* plain_data,
    size_t& plain_length)
{
    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_md5_digest_length(const char* name)
{
    return MD5::digestLength() * 2;
}

CWCRYPTO_API int cw_md5(const char* plain_data, size_t plain_length, char* digest_data, size_t digest_length)
{
    if ((plain_data == NULL) || (plain_length == 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((digest_data == NULL) || (digest_length <= 1))
        return CWCRYPTO_ERROR_INVALID_PARAMS;

    std::string digest = MD5::Calc((const unsigned char*)plain_data, plain_length);
    if (!digest.empty())
    {
        if (digest.length() > (digest_length = 1))
            return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;

        memcpy(digest_data, digest.c_str(), digest.length());
        digest_data[digest.length()] = '\0';
    }

    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_sha256_digest_length(const char* name)
{
    return SHA256::digestLength() * 2;
}

CWCRYPTO_API int cw_sha256(const char* plain_data, size_t plain_length, char* digest_data, size_t digest_length)
{
    if ((plain_data == NULL) || (plain_length == 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((digest_data == NULL) || (digest_length <= 1))
        return CWCRYPTO_ERROR_INVALID_PARAMS;

    std::string digest = SHA256::Calc((const unsigned char*)plain_data, plain_length);
    if (!digest.empty())
    {
        if (digest.length() > (digest_length = 1))
            return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;

        memcpy(digest_data, digest.c_str(), digest.length());
        digest_data[digest.length()] = '\0';
    }

    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_sm3_digest_length(const char* name)
{
    return SM3::digestLength() * 2;
}

CWCRYPTO_API int cw_sm3(const char* plain_data, size_t plain_length, char* digest_data, size_t digest_length)
{
    if ((plain_data == NULL) || (plain_length == 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((digest_data == NULL) || (digest_length <= 1))
        return CWCRYPTO_ERROR_INVALID_PARAMS;

    std::string digest = SM3::Calc((const unsigned char*)plain_data, plain_length);
    if (!digest.empty())
    {
        if (digest.length() > (digest_length = 1))
            return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;

        memcpy(digest_data, digest.c_str(), digest.length());
        digest_data[digest.length()] = '\0';
    }

    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_base64_encode_length(size_t plain_length)
{
    return 0;
}

CWCRYPTO_API int cw_base64_encode(const char *plain_data,
    size_t plain_length,
    char *encoded_data,
    size_t *encoded_length)
{
    if ((plain_data == NULL) || (plain_length == 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((encoded_data == NULL) || (*encoded_length <= 1))
        return CWCRYPTO_ERROR_INVALID_PARAMS;

    std::string base64Str = Base64::Encode((const unsigned char*)plain_data, plain_length);
    if (!base64Str.empty())
    {
        if (base64Str.length() > (*encoded_length - 1))
            return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;

        memcpy(encoded_data, base64Str.c_str(), base64Str.length());
        encoded_data[base64Str.length()] = '\0';
        *encoded_length = base64Str.length();
    }

    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_base64_decode(const char *encoded_data,
    size_t encoded_length,
    char *decoded_data,
    size_t* decoded_length)
{
    if ((encoded_data == NULL) || (encoded_length == 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((decoded_data == NULL) || (*decoded_length <= 1))
        return CWCRYPTO_ERROR_INVALID_PARAMS;

    if (!Base64::Decode((const unsigned char*)encoded_data, encoded_length, (unsigned char*)decoded_data, *decoded_length))
        return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;

    return CWCRYPTO_OK;
}
