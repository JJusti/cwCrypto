#include "crypto/cipher/rc4.h"

#include "openssl/opensslconf.h"
#include "openssl/rc4.h"

struct RC4::IMPL
{
    std::string key_;
};

RC4::RC4():
    impl_(new IMPL)
{
}
    
RC4::~RC4()
{
}

void RC4::SetKey(const std::string& key)
{
    impl_->key_ = key;
}

void RC4::Encrypt(unsigned char* data, uint32_t dataLen)
{
    std::string cipherText;

    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, impl_->key_.length(), (unsigned char *)impl_->key_.c_str());
    cipherText.resize(dataLen);
    ::RC4(&rc4_key, dataLen, data, (unsigned char *)cipherText.data());

    memcpy_s(data, dataLen, cipherText.data(), cipherText.length());
}

void RC4::Decrypt(unsigned char* data, uint32_t dataLen)
{
    Encrypt(data, dataLen);
}

std::string RC4::Encrypt(const std::string &clearText, const std::string &key)  
{  
    std::string cipherText;

    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, key.length(), (unsigned char *)key.c_str());
    cipherText.resize(clearText.size());
    ::RC4(&rc4_key, clearText.size(), (unsigned char*)clearText.data(), (unsigned char *)cipherText.data());

    return cipherText;
}  

std::string RC4::Decrypt(const std::string &cipherText, const std::string &key)  
{
    return Encrypt(cipherText, key);
}
