#include "crypto/hash/sha384.h"

#include "openssl/sha.h"

struct SHA384::IMPL
{
    IMPL():
        hasData_(false)
    {
    }

    SHA512_CTX ctx_;
    bool hasData_;
};

SHA384::SHA384():
    impl_(new IMPL)
{
}

SHA384::~SHA384()
{
}

size_t SHA384::digestLength()
{
    return SHA384_DIGEST_LENGTH;
}

void SHA384::Init()
{
    SHA384_Init(&impl_->ctx_);
    impl_->hasData_ = false;
}

void SHA384::Update(const std::string& src)
{
    if (src.empty())
        return;

    SHA384_Update(&impl_->ctx_, src.c_str(), src.length());
    impl_->hasData_ = true;
}

void SHA384::Update(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return;

    SHA384_Update(&impl_->ctx_, s, len);
    impl_->hasData_ = true;
}

std::string SHA384::Value() const
{
    std::string ret;

    if (impl_->hasData_)
    {
        unsigned char buff[SHA384_DIGEST_LENGTH] = { 0 };
        RawValue(buff, SHA384_DIGEST_LENGTH);

        for (int i = 0; i < SHA384_DIGEST_LENGTH; i++)
        {
            char tmp[8] = {0};
            sprintf(tmp, "%02x", buff[i]);
            ret += tmp;
        }
    }

    return ret;
}

void SHA384::RawValue(unsigned char* buff, size_t len) const
{
    if ((buff == NULL) || (len < SHA384_DIGEST_LENGTH))
        return;

    if (impl_->hasData_)
        SHA384_Final(buff, &impl_->ctx_);
}

std::string SHA384::Calc(const std::string& src)
{
    if (src.empty())
        return std::string();

    SHA384 h;
    h.Init();
    h.Update(src);
    return h.Value();
}

std::string SHA384::Calc(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return std::string();

    SHA384 h;
    h.Init();
    h.Update(s, len);
    return h.Value();
}
