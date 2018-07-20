#include "crypto/hash/sm3.h"
#include "crypto/hash/md5.h"

#include "gtest/gtest.h"

TEST(crypto, sm3)
{
    std::string empty;
    std::string str0("md5");
    std::string md50("1bc29b36f623ba82aaf6724fd3b16718");
    std::string str1("1bc29b36f623ba82aaf6724fd3b16718");
    std::string md51("3ce8b30b8e25ea5d9a83d4a073d6ddf8");
    EXPECT_EQ(SM3::Calc(empty), empty);
    EXPECT_EQ(SM3::Calc(str0), md50);
    EXPECT_EQ(SM3::Calc(str1), md51);

    EXPECT_EQ(SM3::Calc((const unsigned char*)empty.c_str(), empty.length()), empty);
    EXPECT_EQ(SM3::Calc((const unsigned char*)str0.c_str(), str0.length()), md50);
    EXPECT_EQ(SM3::Calc((const unsigned char*)str1.c_str(), str1.length()), md51);

    SM3 h;
    h.Init();
    h.Update(empty);
    EXPECT_EQ(h.Value(), empty);

    h.Init();
    h.Update(str0);
    EXPECT_EQ(h.Value(), md50);

    h.Init();
    h.Update("1bc29b36f623ba82");
    h.Update("aaf6724fd3b16718");
    h.Update("abc");
    EXPECT_EQ(h.Value(), "66d2355bfbc2b8852fd1ff08d4e72ee8");
}
