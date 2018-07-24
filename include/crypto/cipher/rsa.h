#ifndef __CWRSA_H__
#define __CWRSA_H__   1

#include "crypto/base.h"

class CWRSA
{
public:
    CWRSA();
    ~CWRSA();
    
    void SetKey(const std::string& key);

    int32_t PublicEncrypt(unsigned char *data, size_t data_len, unsigned char *key, unsigned char *encrypted);
    int32_t PrivateDecrypt(unsigned char *enc_data, size_t data_len, unsigned char *key, unsigned char *decrypted);
    int32_t PrivateEncrypt(unsigned char *data, size_t data_len, unsigned char *key, unsigned char *encrypted);
    int32_t PublicDecrypt(unsigned char * enc_data, size_t data_len, unsigned char *key, unsigned char *decrypted);

private:
    class IMPL;
    std::unique_ptr<IMPL> impl_;
};

#endif // __RSA_H__
