#include "crypto/cipher/aes.h"

#include "openssl/aes.h"

AES::AES():
    mode_(MODE::CBC)
{
}

AES::AES(MODE mode):
    mode_(mode)
{
}

AES::~AES()
{
}

void AES::SetMode(MODE mode)
{
    mode_ = mode;
}

MODE AES::GetMode() const
{
    return mode_;
}

bool AES::Encrypt(const std::string& plainText, const std::string& key, std::string& cipherText)
{
    std::string& strOut = cipherText;
    unsigned int uEncLen = 0;
    unsigned int uLen = (unsigned int)plainText.length();

    if (plainText.empty() || plainText.empty())
        return false;

    unsigned char szKey[AES_BLOCK_SIZE + 1] = { 0 };
    unsigned char szIV[AES_BLOCK_SIZE + 1] = { 0 };
    if (key.length() < AES_BLOCK_SIZE)
    {
        memcpy(szKey, key.c_str(), key.length());
        memcpy(szIV, key.c_str(), key.length());
    }
    else
    {
        memcpy(szKey, key.c_str(), AES_BLOCK_SIZE);
        memcpy(szIV, key.c_str(), AES_BLOCK_SIZE);
    }

    AES_KEY aesKey;
    if (AES_set_encrypt_key(szKey, AES_BLOCK_SIZE * 8, &aesKey) < 0)
        return false;

    unsigned char szBufIn[AES_BLOCK_SIZE + 1] = { 0 };
    unsigned char szBufOut[AES_BLOCK_SIZE + 1] = { 0 };
    
    while (uEncLen < uLen)
    {
        memset(szBufIn, 0, sizeof(szBufIn));
        memset(szBufOut, 0, sizeof(szBufOut));

        int tmpLen = uLen - uEncLen;
        if (tmpLen > AES_BLOCK_SIZE)
            tmpLen = AES_BLOCK_SIZE;
        memcpy(szBufIn, plainText.c_str() + uEncLen, tmpLen * sizeof(unsigned char));

        switch (mode_)
        {
        case ECB:
            AES_ecb_encrypt(szBufIn, szBufOut, &aesKey, AES_ENCRYPT);
            break;
        case CBC:
            AES_cbc_encrypt(szBufIn, szBufOut, tmpLen, &aesKey, szIV, AES_ENCRYPT);
            break;
        default:
            break;
        }
        strOut.append((char*)szBufOut, AES_BLOCK_SIZE);
        uEncLen += tmpLen;
    }

    return true;
}

bool AES::Encrypt(const unsigned char *data, size_t dataLen, const std::string& key, std::vector<unsigned char>& cipherBuff)
{
    return false;
}

bool AES::Decrypt(const std::string& plainText, const std::string& key, std::string& cipherText)
{
    std::string& strOut = cipherText;
    unsigned int uDecLen = 0;
    unsigned int uLen = (unsigned int)plainText.length();

    if (plainText.empty() || key.empty())
        return false;

    unsigned char szKey[AES_BLOCK_SIZE + 1] = { 0 };
    unsigned char szIV[AES_BLOCK_SIZE + 1] = { 0 };
    if (key.length() < AES_BLOCK_SIZE)
    {
        memcpy(szKey, key.c_str(), key.length());
        memcpy(szIV, key.c_str(), key.length());
    }
    else
    {
        memcpy(szKey, key.c_str(), AES_BLOCK_SIZE);
        memcpy(szIV, key.c_str(), AES_BLOCK_SIZE);
    }

    AES_KEY aesKey;
    if (AES_set_decrypt_key(szKey, AES_BLOCK_SIZE * 8, &aesKey) < 0)
        return false;

    unsigned char szBufIn[AES_BLOCK_SIZE + 1] = { 0 };
    unsigned char szBufOut[AES_BLOCK_SIZE + 1] = { 0 };

    while (uDecLen < uLen)
    {
        memset(szBufIn, 0, sizeof(szBufIn));
        memset(szBufOut, 0, sizeof(szBufOut));

        int tmpLen = uLen - uDecLen;
        if (tmpLen > AES_BLOCK_SIZE)
            tmpLen = AES_BLOCK_SIZE;
        memcpy(szBufIn, plainText.c_str() + uDecLen, tmpLen * sizeof(unsigned char));

        switch (mode_)
        {
        case ECB:
            AES_ecb_encrypt(szBufIn, szBufOut, &aesKey, AES_DECRYPT);
            break;
        case CBC:
            AES_cbc_encrypt(szBufIn, szBufOut, tmpLen, &aesKey, szIV, AES_DECRYPT);
            break;
        default:
            break;
        }
        strOut += (char*)szBufOut;
        uDecLen += tmpLen;
    }

    return true;
}

bool AES::Decrypt(const unsigned char *cipherData, size_t dataLen, const std::string& key, std::vector<unsigned char>& plainData)
{
    return false;
}
