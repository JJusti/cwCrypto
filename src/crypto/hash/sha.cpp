#include "crypto/hash/sha.h"

#include "openssl/sha.h"

struct SHA::IMPL
{
    IMPL():
        hasData_(false)
    {
    }

    SHA_CTX ctx_;
    bool hasData_;
};

SHA::SHA():
    impl_(new IMPL)
{
}

SHA::~SHA()
{
}

size_t SHA::digestLength()
{
    return SHA_DIGEST_LENGTH;
}

void SHA::Init()
{
    SHA_Init(&impl_->ctx_);
    impl_->hasData_ = false;
}

void SHA::Update(const std::string& src)
{
    if (src.empty())
        return;

    SHA_Update(&impl_->ctx_, src.c_str(), src.length());
    impl_->hasData_ = true;
}

void SHA::Update(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return;

    SHA_Update(&impl_->ctx_, s, len);
    impl_->hasData_ = true;
}

std::string SHA::Value() const
{
    std::string ret;

    if (impl_->hasData_)
    {
        unsigned char buff[SHA_DIGEST_LENGTH] = { 0 };
        RawValue(buff, SHA_DIGEST_LENGTH);

        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        {
            char tmp[8] = {0};
            sprintf(tmp, "%02x", buff[i]);
            ret += tmp;
        }
    }

    return ret;
}

void SHA::RawValue(unsigned char* buff, size_t len) const
{
    if ((buff == NULL) || (len < SHA_DIGEST_LENGTH))
        return;

    if (impl_->hasData_)
        SHA_Final(buff, &impl_->ctx_);
}

std::string SHA::Calc(const std::string& src)
{
    if (src.empty())
        return std::string();

    SHA h;
    h.Init();
    h.Update(src);
    return h.Value();
}

std::string SHA::Calc(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return std::string();

    SHA h;
    h.Init();
    h.Update(s, len);
    return h.Value();
}
