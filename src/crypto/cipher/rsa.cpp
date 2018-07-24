#include "crypto/cipher/rsa.h"

#include "openssl/opensslconf.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"

RSA* CreateRSA(unsigned char *key, bool isPublicKey)
{
    BIO *keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL)
        return NULL;

    RSA *rsa = NULL;
    if (isPublicKey)
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    else
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    return rsa;
}

RSA* CreateRSAFromPEMFile(char* filename, bool isPublicKey)
{
    RSA *rsa = NULL;

    FILE *fp = fopen(filename, "rb");
    if (fp != NULL)
    {
        rsa = RSA_new();
        if (isPublicKey)
            rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
        else
            rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
        fclose(fp);
    }

    return rsa;
}

void FreeRSA(RSA *rsa)
{
    if (rsa != NULL)
    {
        RSA_free(rsa);
        rsa = NULL;
    }
}

class CWRSA::IMPL
{
public:
    IMPL():
        publicKey_(NULL),
        privateKey_(NULL),
        padding_(RSA_PKCS1_PADDING)
    {
    };

    ~IMPL()
    {
    }

    RSA *publicKey_;
    RSA *privateKey_;
    int32_t padding_;
};

CWRSA::CWRSA():
    impl_(new IMPL())
{
}
    
CWRSA::~CWRSA()
{
}

void CWRSA::SetKey(const std::string& key)
{
}

int CWRSA::PublicEncrypt(unsigned char *data, size_t data_len, unsigned char *key, unsigned char *encrypted)
{
    RSA * rsa = CreateRSA(key, true);
    return RSA_public_encrypt(data_len, data, encrypted, rsa, RSA_PKCS1_PADDING);
}

int CWRSA::PrivateDecrypt(unsigned char *enc_data, size_t data_len, unsigned char *key, unsigned char *decrypted)
{
    RSA * rsa = CreateRSA(key, false);
    return RSA_private_decrypt(data_len, enc_data, decrypted, rsa, RSA_PKCS1_PADDING);
}

int CWRSA::PrivateEncrypt(unsigned char *data, size_t data_len, unsigned char *key, unsigned char *encrypted)
{
    RSA * rsa = CreateRSA(key, false);
    return RSA_private_encrypt(data_len, data, encrypted, rsa, RSA_PKCS1_PADDING);
}

int CWRSA::PublicDecrypt(unsigned char * enc_data, size_t data_len, unsigned char *key, unsigned char *decrypted)
{
    RSA * rsa = CreateRSA(key, true);
    return RSA_public_decrypt(data_len, enc_data, decrypted, rsa, RSA_PKCS1_PADDING);
}

//void CWRSA::Encrypt(unsigned char* data, uint32_t dataLen)
//{
//    std::string pemFilePath;
//    FILE* hPubKeyFile = fopen(pemFilePath.c_str(), "rb");
//	if( hPubKeyFile == NULL )
//		return ; 
//
//    std::string strRet;
//	RSA* pRSAPublicKey = RSA_new();
//    
//	if (PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
//		return;
// 
//	int nLen = RSA_size(pRSAPublicKey);
//	char* pEncode = new char[nLen + 1];
//	int ret = RSA_public_encrypt(dataLen, data, (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
//	if (ret >= 0)
//		strRet = std::string(pEncode, ret);
//	
//    delete[] pEncode;
//	RSA_free(pRSAPublicKey);
//	fclose(hPubKeyFile);
//	CRYPTO_cleanup_all_ex_data();
//}
//
//void CWRSA::Decrypt(unsigned char* data, uint32_t dataLen)
//{
//    std::string pemFilePath;
//    FILE* hPriKeyFile = fopen(pemFilePath.c_str(),"rb");
//	if( hPriKeyFile == NULL )
//		return;
//	
//    std::string strRet;
//	RSA* pRSAPriKey = RSA_new();
//	if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
//		return ;
//
//    int nLen = RSA_size(pRSAPriKey);
//	char* pDecode = new char[nLen+1];
// 
//	int ret = RSA_private_decrypt(dataLen, data, (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
//	if(ret >= 0)
//		strRet = std::string((char*)pDecode, ret);
//
//    delete [] pDecode;
//	RSA_free(pRSAPriKey);
//	fclose(hPriKeyFile);
//	CRYPTO_cleanup_all_ex_data();
//}
