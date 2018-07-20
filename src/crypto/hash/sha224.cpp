#include "crypto/hash/sha224.h"

#include "openssl/sha.h"

struct SHA224::IMPL
{
    IMPL():
        hasData_(false)
    {
    }

    SHA256_CTX ctx_;
    bool hasData_;
};

SHA224::SHA224():
    impl_(new IMPL)
{
}

SHA224::~SHA224()
{
}

size_t SHA224::digestLength()
{
    return SHA224_DIGEST_LENGTH;
}

void SHA224::Init()
{
    SHA224_Init(&impl_->ctx_);
    impl_->hasData_ = false;
}

void SHA224::Update(const std::string& src)
{
    if (src.empty())
        return;

    SHA224_Update(&impl_->ctx_, src.c_str(), src.length());
    impl_->hasData_ = true;
}

void SHA224::Update(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return;

    SHA224_Update(&impl_->ctx_, s, len);
    impl_->hasData_ = true;
}

std::string SHA224::Value() const
{
    std::string ret;

    if (impl_->hasData_)
    {
        unsigned char buff[SHA224_DIGEST_LENGTH] = { 0 };
        RawValue(buff, SHA224_DIGEST_LENGTH);

        for (int i = 0; i < SHA224_DIGEST_LENGTH; i++)
        {
            char tmp[8] = {0};
            sprintf(tmp, "%02x", buff[i]);
            ret += tmp;
        }
    }

    return ret;
}

void SHA224::RawValue(unsigned char* buff, size_t len) const
{
    if ((buff == NULL) || (len < SHA224_DIGEST_LENGTH))
        return;

    if (impl_->hasData_)
        SHA224_Final(buff, &impl_->ctx_);
}

std::string SHA224::Calc(const std::string& src)
{
    if (src.empty())
        return std::string();

    SHA224 h;
    h.Init();
    h.Update(src);
    return h.Value();
}

std::string SHA224::Calc(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return std::string();

    SHA224 h;
    h.Init();
    h.Update(s, len);
    return h.Value();
}
