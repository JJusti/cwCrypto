#include "crypto/hash/sha256.h"

#include "openssl/sha.h"

struct SHA256::IMPL
{
    IMPL():
        hasData_(false)
    {
    }

    SHA256_CTX ctx_;
    bool hasData_;
};

SHA256::SHA256():
    impl_(new IMPL)
{
}

SHA256::~SHA256()
{
}

size_t SHA256::digestLength()
{
    return SHA256_DIGEST_LENGTH;
}

void SHA256::Init()
{
    SHA256_Init(&impl_->ctx_);
    impl_->hasData_ = false;
}

void SHA256::Update(const std::string& src)
{
    if (src.empty())
        return;

    SHA256_Update(&impl_->ctx_, src.c_str(), src.length());
    impl_->hasData_ = true;
}

void SHA256::Update(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return;

    SHA256_Update(&impl_->ctx_, s, len);
    impl_->hasData_ = true;
}

std::string SHA256::Value() const
{
    std::string ret;

    if (impl_->hasData_)
    {
        unsigned char buff[SHA256_DIGEST_LENGTH] = { 0 };
        RawValue(buff, SHA256_DIGEST_LENGTH);

        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            char tmp[8] = {0};
            sprintf(tmp, "%02x", buff[i]);
            ret += tmp;
        }
    }

    return ret;
}

void SHA256::RawValue(unsigned char* buff, size_t len) const
{
    if ((buff == NULL) || (len < SHA256_DIGEST_LENGTH))
        return;

    if (impl_->hasData_)
        SHA256_Final(buff, &impl_->ctx_);
}

std::string SHA256::Calc(const std::string& src)
{
    if (src.empty())
        return std::string();

    SHA256 h;
    h.Init();
    h.Update(src);
    return h.Value();
}

std::string SHA256::Calc(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return std::string();

    SHA256 h;
    h.Init();
    h.Update(s, len);
    return h.Value();
}
