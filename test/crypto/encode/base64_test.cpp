#include "crypto/encode/base64.h"
#include "gtest/gtest.h"

TEST(crypto, base64_encode_string)
{
    EXPECT_EQ(Base64::Encode(std::string("")), std::string(""));
    EXPECT_EQ(Base64::Encode(std::string("a")), std::string("YQ=="));
    EXPECT_EQ(Base64::Encode(std::string("ab")), std::string("YWI="));
    EXPECT_EQ(Base64::Encode(std::string("abc")), std::string("YWJj"));
    EXPECT_EQ(Base64::Encode(std::string("abcd")), std::string("YWJjZA=="));
    EXPECT_EQ(Base64::Encode(std::string("this is a example")), std::string("dGhpcyBpcyBhIGV4YW1wbGU="));
}

TEST(crypto, base64_decode_string)
{
    std::string decoded;
    EXPECT_TRUE(Base64::Decode(std::string(""), decoded));
    EXPECT_EQ(decoded, std::string(""));

    EXPECT_TRUE(Base64::Decode(std::string("YQ=="), decoded));
    EXPECT_EQ(decoded, std::string("a"));

    EXPECT_TRUE(Base64::Decode(std::string("YWI="), decoded));
    EXPECT_EQ(decoded, std::string("ab"));

    EXPECT_TRUE(Base64::Decode(std::string("YWJj"), decoded));
    EXPECT_EQ(decoded, std::string("abc"));

    EXPECT_TRUE(Base64::Decode(std::string("YWJjZA=="), decoded));
    EXPECT_EQ(decoded, std::string("abcd"));

    EXPECT_TRUE(Base64::Decode(std::string("dGhpcyBpcyBhIGV4YW1wbGU="), decoded));
    EXPECT_EQ(decoded, std::string("this is a example"));
}

TEST(crypto, base64_encode_buffer)
{
    EXPECT_EQ(Base64::Encode(NULL, 0), "");
    EXPECT_EQ(Base64::Encode(NULL, -1), "");
    EXPECT_EQ(Base64::Encode(NULL, 1), "");

    unsigned char buff[] = "abcd";
    EXPECT_EQ(Base64::Encode(buff, 0), "");
    EXPECT_EQ(Base64::Encode(buff, 1), "YQ==");
    EXPECT_EQ(Base64::Encode(buff, 2), "YWI=");
    EXPECT_EQ(Base64::Encode(buff, 3), "YWJj");
    EXPECT_EQ(Base64::Encode(buff, 4), "YWJjZA==");

    std::string str("this is a example");
    std::vector<unsigned char> v;
    for (size_t i = 0; i < str.length(); i++)
    {
        v.push_back(str[i]);
    }

    EXPECT_EQ(Base64::Encode(v.data(), v.size()), std::string("dGhpcyBpcyBhIGV4YW1wbGU="));
}

TEST(crypto, base64_decode_buffer)
{
    {
        unsigned char buff[] = { 0 };
        std::vector<unsigned char> decoded;
        EXPECT_TRUE(Base64::Decode(buff, 0, decoded));
        EXPECT_EQ(decoded.size(), 0);
    }

    {
        unsigned char buff[] = { 'Y', 'Q', '=', '=' };
        std::vector<unsigned char> decoded;
        EXPECT_TRUE(Base64::Decode(buff, sizeof(buff), decoded));
        EXPECT_EQ(decoded[0], 'a');
    }
}
