#include "crypto/cipher/des.h"

#include "openssl/des.h"

DES::DES()
{
}

DES::DES(MODE)
{
}

DES::~DES()
{
}

bool DES::Encrypt(const std::string& plainText, const std::string& key, std::string& cipherText)
{
    return false;
}

bool DES::Decrypt(const std::string& plainText, const std::string& key, std::string& cipherText)
{
    return false;
}

void DES::Encrypt(MODE m, const std::string& plainText, const std::string& key, std::string& cipherText)
{

}

void DES::Decrypt(MODE m, const std::string& cipherText, const std::string& key, std::string& plainText)
{

}
