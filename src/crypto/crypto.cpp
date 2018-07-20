#include "crypto/crypto.h"

#include "crypto/hash/md5.h"
#include "crypto/hash/sha256.h"
#include "crypto/hash/sm3.h"

#include "crypto/encode/base64.h"

CWCRYPTO_API int cw_md5_digest_length(const char* name)
{
    return MD5::digestLength() * 2;
}

CWCRYPTO_API int cw_md5(const unsigned char* plain_data, size_t plain_length, unsigned char* digest_data, size_t digest_length)
{
    if ((plain_data == NULL) || (plain_length == 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((digest_data == NULL) || (digest_length <= 1))
        return CWCRYPTO_ERROR_INVALID_PARAMS;

    std::string digest = MD5::Calc(plain_data, plain_length);
    if (!digest.empty())
    {
        if (digest.length() > (digest_length = 1))
            return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;

        memcpy(digest_data, digest.c_str(), digest.length());
        digest_data[digest.length()] = '\0';
        *digest_data = digest.length();
    }

    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_sha256_digest_length(const char* name)
{
    return SHA256::digestLength() * 2;
}

CWCRYPTO_API int cw_sha256(const unsigned char* plain_data, size_t plain_length, unsigned char* digest_data, size_t digest_length)
{
    if ((plain_data == NULL) || (plain_length == 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((digest_data == NULL) || (digest_length <= 1))
        return CWCRYPTO_ERROR_INVALID_PARAMS;

    std::string digest = SHA256::Calc(plain_data, plain_length);
    if (!digest.empty())
    {
        if (digest.length() > (digest_length = 1))
            return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;

        memcpy(digest_data, digest.c_str(), digest.length());
        digest_data[digest.length()] = '\0';
        *digest_data = digest.length();
    }

    return CWCRYPTO_OK;
}

CWCRYPTO_API int cw_sm3_digest_length(const char* name)
{
    return SM3::digestLength() * 2;
}

CWCRYPTO_API int cw_sm3(const unsigned char* plain_data, size_t plain_length, unsigned char* digest_data, size_t digest_length)
{
    if ((plain_data == NULL) || (plain_length == 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((digest_data == NULL) || (digest_length <= 1))
        return CWCRYPTO_ERROR_INVALID_PARAMS;

    std::string digest = SM3::Calc(plain_data, plain_length);
    if (!digest.empty())
    {
        if (digest.length() > (digest_length = 1))
            return CWCRYPTO_ERROR_NOT_ENOUGH_MEMORY;

        memcpy(digest_data, digest.c_str(), digest.length());
        digest_data[digest.length()] = '\0';
        *digest_data = digest.length();
    }

    return CWCRYPTO_OK;
}

int cw_base64_encode_length(size_t plain_length)
{
    return 0;
}

int cw_base64_encode(const unsigned char *plain_data, size_t plain_length, unsigned char *encoded_data, size_t *encoded_length)
{
    if ((plain_data == NULL) || (plain_length == 0))
        return CWCRYPTO_ERROR_INVALID_PARAMS;
    if ((encoded_data == NULL) || (*encoded_length <= 1))
        return CWCRYPTO_ERROR_INVALID_PARAMS;

    std::string base64Str = Base64::Encode(plain_data, plain_length);
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

int cw_base64_decode(const unsigned char *encoded_data, size_t encoded_length, unsigned char *decoded_data, size_t* decoded_length)
{
    return 0;
}
