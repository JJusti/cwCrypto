#include "crypto/cipher/sm4.h"

#include "openssl/sms4.h"

CWSM4::CWSM4() :
    mode_(MODE::CBC)
{
}

CWSM4::CWSM4(MODE mode) :
    mode_(mode)
{
}

CWSM4::~CWSM4()
{
}

void CWSM4::SetMode(MODE mode)
{
    mode_ = mode;
}

MODE CWSM4::GetMode() const
{
    return mode_;
}

bool CWSM4::Encrypt(const std::string& plainText, const std::string& key, std::string& cipherText)
{
    std::string& strOut = cipherText;
    unsigned int uEncLen = 0;
    unsigned int uLen = (unsigned int)plainText.length();

    if (plainText.empty() || plainText.empty())
    {
        return false;
    }

    unsigned char szKey[SMS4_BLOCK_SIZE + 1] = { 0 };
    if (key.length() < SMS4_BLOCK_SIZE)
    {
        memcpy(szKey, key.c_str(), key.length());
    }
    else
    {
        memcpy(szKey, key.c_str(), SMS4_BLOCK_SIZE);
    }

    sms4_key_t SM4Key;
    sms4_set_encrypt_key(&SM4Key, szKey);

    unsigned char szBufIn[SMS4_BLOCK_SIZE + 1] = { 0 };
    unsigned char szBufOut[SMS4_BLOCK_SIZE + 1] = { 0 };
    unsigned char szIV[SMS4_BLOCK_SIZE + 1] = { 0 };
    while (uEncLen < uLen)
    {

        memset(szIV, 0, sizeof(szIV));
        memset(szBufIn, 0, sizeof(szBufIn));
        memset(szBufOut, 0, sizeof(szBufOut));

        int tmpLen = uLen - uEncLen;
        if (tmpLen > SMS4_BLOCK_SIZE)
        {
            tmpLen = SMS4_BLOCK_SIZE;
        }
        memcpy(szBufIn, plainText.c_str() + uEncLen, tmpLen * sizeof(unsigned char));
        switch (mode_)
        {
        case ECB:
            sms4_ecb_encrypt(szBufIn, szBufOut, &SM4Key, 1);
            break;
        case CBC:
            sms4_cbc_encrypt(szBufIn, szBufOut, tmpLen, &SM4Key, szIV, 1);
            break;
        default:
            break;
        }
        strOut += (char*)szBufOut;
        uEncLen += tmpLen;
    }

    return true;
}

bool CWSM4::Encrypt(const unsigned char *data, size_t dataLen, const std::string& key, std::vector<unsigned char>& cipherBuff)
{
    return false;
}

bool CWSM4::Decrypt(const std::string& plainText, const std::string& key, std::string& cipherText)
{
    if (mode_ == MODE::ECB)
    {

    }

    std::string& strOut = cipherText;
    unsigned int uDecLen = 0;
    unsigned int uLen = (unsigned int)plainText.length();

    if (plainText.empty() || key.empty())
    {
        return false;
    }

    unsigned char szKey[SMS4_BLOCK_SIZE + 1] = { 0 };
    if (key.length() < SMS4_BLOCK_SIZE)
    {
        memcpy(szKey, key.c_str(), key.length());
    }
    else
    {
        memcpy(szKey, key.c_str(), SMS4_BLOCK_SIZE);
    }

    sms4_key_t SM4Key;
    sms4_set_decrypt_key(&SM4Key, szKey);

    unsigned char szBufIn[SMS4_BLOCK_SIZE + 1] = { 0 };
    unsigned char szBufOut[SMS4_BLOCK_SIZE + 1] = { 0 };
    unsigned char szIV[SMS4_BLOCK_SIZE + 1] = { 0 };
    while (uDecLen < uLen)
    {
        memset(szIV, 0, sizeof(szIV));
        memset(szBufIn, 0, sizeof(szBufIn));
        memset(szBufOut, 0, sizeof(szBufOut));

        int tmpLen = uLen - uDecLen;
        if (tmpLen > SMS4_BLOCK_SIZE)
        {
            tmpLen = SMS4_BLOCK_SIZE;
        }
        memcpy(szBufIn, plainText.c_str() + uDecLen, tmpLen * sizeof(unsigned char));
        switch (mode_)
        {
        case ECB:
            sms4_ecb_encrypt(szBufIn, szBufOut, &SM4Key, 0);
            break;
        case CBC:
            sms4_cbc_encrypt(szBufIn, szBufOut, tmpLen, &SM4Key, szIV, 0);
            break;
        default:
            break;
        }
        strOut += (char*)szBufOut;
        uDecLen += tmpLen;
    }

    return true;
}

bool CWSM4::Decrypt(const unsigned char *cipherData, size_t dataLen, const std::string& key, std::vector<unsigned char>& plainData)
{
    return false;
}
