#include "crypto/hash/sm3.h"

#include "openssl/sm3.h"

struct SM3::IMPL
{
    IMPL() :
        hasData_(false)
    {
    }

    sm3_ctx_t ctx_;
    bool hasData_;
};

SM3::SM3():
    impl_(new IMPL)
{
}

SM3::~SM3()
{
}

size_t SM3::digestLength()
{
    return SM3_DIGEST_LENGTH;
}

void SM3::Init()
{
    sm3_init(&impl_->ctx_);
    impl_->hasData_ = false;
}

void SM3::Update(const std::string& src)
{
    if (src.empty())
        return;

    sm3_update(&impl_->ctx_, (const unsigned char*)src.c_str(), src.length());
    impl_->hasData_ = true;
}

void SM3::Update(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return;

    sm3_update(&impl_->ctx_, s, len);
    impl_->hasData_ = true;
}

std::string SM3::Value() const
{
    std::string ret;

    if (impl_->hasData_)
    {
        unsigned char buff[SM3_DIGEST_LENGTH] = { 0 };
        RawValue(buff, SM3_DIGEST_LENGTH);

        for (int i = 0; i < SM3_DIGEST_LENGTH; i++)
        {
            char tmp[8] = {0};
            sprintf(tmp, "%02x", buff[i]);
            ret += tmp;
        }
    }

    return ret;
}

void SM3::RawValue(unsigned char* buff, size_t len) const
{
    if ((buff == NULL) || (len < SM3_DIGEST_LENGTH))
        return;

    if (impl_->hasData_)
        sm3_final(&impl_->ctx_, buff);
}

std::string SM3::Calc(const std::string& src)
{
    if (src.empty())
        return std::string();

    SM3 h;
    h.Init();
    h.Update(src);
    return h.Value();
}

std::string SM3::Calc(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return std::string();

    SM3 h;
    h.Init();
    h.Update(s, len);
    return h.Value();
}
