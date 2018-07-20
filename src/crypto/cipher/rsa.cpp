#include "crypto/cipher/rsa.h"

#include "openssl/opensslconf.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"

struct CWRSA::IMPL
{
    std::string key_;
};

CWRSA::CWRSA():
    impl_(new IMPL)
{
}
    
CWRSA::~CWRSA()
{
}

void CWRSA::SetKey(const std::string& key)
{
    impl_->key_ = key;
}

void CWRSA::Encrypt(unsigned char* data, uint32_t dataLen)
{
    std::string pemFilePath;
    FILE* hPubKeyFile = fopen(pemFilePath.c_str(), "rb");
	if( hPubKeyFile == NULL )
		return ; 

    std::string strRet;
	RSA* pRSAPublicKey = RSA_new();
    
	if (PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
		return;
 
	int nLen = RSA_size(pRSAPublicKey);
	char* pEncode = new char[nLen + 1];
	int ret = RSA_public_encrypt(dataLen, data, (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(pEncode, ret);
	
    delete[] pEncode;
	RSA_free(pRSAPublicKey);
	fclose(hPubKeyFile);
	CRYPTO_cleanup_all_ex_data();
}

void CWRSA::Decrypt(unsigned char* data, uint32_t dataLen)
{
    std::string pemFilePath;
    FILE* hPriKeyFile = fopen(pemFilePath.c_str(),"rb");
	if( hPriKeyFile == NULL )
		return;
	
    std::string strRet;
	RSA* pRSAPriKey = RSA_new();
	if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
		return ;

    int nLen = RSA_size(pRSAPriKey);
	char* pDecode = new char[nLen+1];
 
	int ret = RSA_private_decrypt(dataLen, data, (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
	if(ret >= 0)
		strRet = std::string((char*)pDecode, ret);

    delete [] pDecode;
	RSA_free(pRSAPriKey);
	fclose(hPriKeyFile);
	CRYPTO_cleanup_all_ex_data();
}

std::string CWRSA::Encrypt(const std::string &clearText, const std::string &key)
{
    std::string cipherText;
    return cipherText;
}  

std::string CWRSA::Decrypt(const std::string &cipherText, const std::string &key)
{
    return Encrypt(cipherText, key);
}
