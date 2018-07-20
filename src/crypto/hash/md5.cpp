#include "crypto/hash/md5.h"

#include "openssl/md5.h"

struct MD5::IMPL
{
    IMPL():
        hasData_(false)
    {
    }

    MD5_CTX ctx_;
    bool hasData_;
};

MD5::MD5():
    impl_(new IMPL)
{
}

MD5::~MD5()
{
}

size_t MD5::digestLength()
{
    return MD5_DIGEST_LENGTH;
}

void MD5::Init()
{
    MD5_Init(&impl_->ctx_);
    impl_->hasData_ = false;
}

void MD5::Update(const std::string& src)
{
    if (src.empty())
        return;

    MD5_Update(&impl_->ctx_, src.c_str(), src.length());
    impl_->hasData_ = true;
}

void MD5::Update(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return;

    MD5_Update(&impl_->ctx_, s, len);
    impl_->hasData_ = true;
}

std::string MD5::Value() const
{
    std::string ret;

    if (impl_->hasData_)
    {
        unsigned char buff[MD5_DIGEST_LENGTH] = { 0 };
        RawValue(buff, MD5_DIGEST_LENGTH);

        for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
        {
            char tmp[8] = {0};
            sprintf(tmp, "%02x", buff[i]);
            ret += tmp;
        }
    }

    return ret;
}

void MD5::RawValue(unsigned char* buff, size_t len) const
{
    if ((buff == NULL) || (len < MD5_DIGEST_LENGTH))
        return;

    if (impl_->hasData_)
        MD5_Final(buff, &impl_->ctx_);
}

std::string MD5::Calc(const std::string& src)
{
    if (src.empty())
        return std::string();

    MD5 md5;
    md5.Init();
    md5.Update(src);
    return md5.Value();
}

std::string MD5::Calc(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return std::string();

    MD5 h;
    h.Init();
    h.Update(s, len);
    return h.Value();
}
