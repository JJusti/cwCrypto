#ifndef __CWRSA_H__
#define __CWRSA_H__   1

#include "crypto/base.h"

class CWRSA
{
public:
    CWRSA();
    ~CWRSA();
    
    void SetKey(const std::string& key);
    void Encrypt(unsigned char* data, uint32_t dataLen);
    void Decrypt(unsigned char* data, uint32_t dataLen);

public:

    static std::string Encrypt(const std::string &clearText, const std::string &key);
    static std::string Decrypt(const std::string &cipherText, const std::string &key);

private:
    struct IMPL;
    std::unique_ptr<IMPL> impl_;
};

#endif // __RSA_H__
