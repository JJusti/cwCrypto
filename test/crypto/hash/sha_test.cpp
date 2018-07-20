#include "crypto/hash/sha.h"
#include "crypto/hash/sha224.h"
#include "gtest/gtest.h"

TEST(crypto, sha)
{
    //std::string empty;
    //std::string str0("sha");
    //std::string hash0("1bc29b36f623ba82aaf6724fd3b16718");
    //std::string str1("1bc29b36f623ba82aaf6724fd3b16718");
    //std::string hash1("3ce8b30b8e25ea5d9a83d4a073d6ddf8");
    //EXPECT_EQ(SHA::Calc(empty), empty);
    //EXPECT_EQ(SHA::Calc(str0), hash0);
    //EXPECT_EQ(SHA::Calc(str1), hash1);

    //EXPECT_EQ(SHA::Calc((const unsigned char*)empty.c_str(), empty.length()), empty);
    //EXPECT_EQ(SHA::Calc((const unsigned char*)str0.c_str(), str0.length()), hash0);
    //EXPECT_EQ(SHA::Calc((const unsigned char*)str1.c_str(), str1.length()), hash1);

    //SHA h;
    //h.Init();
    //h.Update(empty);
    //EXPECT_EQ(h.Value(), empty);

    //h.Init();
    //h.Update(str0);
    //EXPECT_EQ(h.Value(), hash0);

    //h.Init();
    //h.Update("1bc29b36f623ba82");
    //h.Update("aaf6724fd3b16718");
    //h.Update("abc");
    //EXPECT_EQ(h.Value(), "66d2355bfbc2b8852fd1ff08d4e72ee8");
}
