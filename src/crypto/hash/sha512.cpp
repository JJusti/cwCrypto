#include "crypto/hash/sha512.h"

#include "openssl/sha.h"

struct SHA512::IMPL
{
    IMPL():
        hasData_(false)
    {
    }

    SHA512_CTX ctx_;
    bool hasData_;
};

SHA512::SHA512():
    impl_(new IMPL)
{
}

SHA512::~SHA512()
{
}

size_t SHA512::digestLength()
{
    return SHA512_DIGEST_LENGTH;
}

void SHA512::Init()
{
    SHA512_Init(&impl_->ctx_);
    impl_->hasData_ = false;
}

void SHA512::Update(const std::string& src)
{
    if (src.empty())
        return;

    SHA512_Update(&impl_->ctx_, src.c_str(), src.length());
    impl_->hasData_ = true;
}

void SHA512::Update(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return;

    SHA512_Update(&impl_->ctx_, s, len);
    impl_->hasData_ = true;
}

std::string SHA512::Value() const
{
    std::string ret;

    if (impl_->hasData_)
    {
        unsigned char buff[SHA512_DIGEST_LENGTH] = { 0 };
        RawValue(buff, SHA512_DIGEST_LENGTH);

        for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        {
            char tmp[8] = {0};
            sprintf(tmp, "%02x", buff[i]);
            ret += tmp;
        }
    }

    return ret;
}

void SHA512::RawValue(unsigned char* buff, size_t len) const
{
    if ((buff == NULL) || (len < SHA512_DIGEST_LENGTH))
        return;

    if (impl_->hasData_)
        SHA512_Final(buff, &impl_->ctx_);
}

std::string SHA512::Calc(const std::string& src)
{
    if (src.empty())
        return std::string();

    SHA512 h;
    h.Init();
    h.Update(src);
    return h.Value();
}

std::string SHA512::Calc(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return std::string();

    SHA512 h;
    h.Init();
    h.Update(s, len);
    return h.Value();
}
