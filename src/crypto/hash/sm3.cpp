#include "crypto/hash/sm3.h"

struct SM3::IMPL
{
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
    return 0;
}

void SM3::Init()
{
}

void SM3::Update(const std::string& src)
{
    if (src.empty())
        return;
}

void SM3::Update(const unsigned char* s, size_t len)
{
    if ((s == nullptr) || (len == 0))
        return;
}

std::string SM3::Value() const
{
    std::string ret;
    return ret;
}

void SM3::RawValue(unsigned char* buff, size_t len) const
{
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
