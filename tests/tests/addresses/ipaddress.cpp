#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>

#include <pcapwrapper/helpers/helper.h>
#include <pcapwrapper/helpers/strutils.h>
#include <pcapwrapper/network/addresses/ipaddress.h>

TEST(IpAddress, Constexpr_strcnt) {
    constexpr auto cnt0 = PCAP::PCAPStrUtils::strcnt("0.0.0.0", '.');
    EXPECT_EQ(cnt0, 3);

    constexpr auto cnt1 = PCAP::PCAPStrUtils::strcnt("0.0.0.0", ':');
    EXPECT_EQ(cnt1, 0);

    constexpr auto cnt2 = PCAP::PCAPStrUtils::strcnt("FF:FF:FF:FF:FF:FF", ':');
    EXPECT_EQ(cnt2, 5);

    constexpr auto cnt3 = PCAP::PCAPStrUtils::strcnt("FF:FF:FF:FF:FF:FF", '.');
    EXPECT_EQ(cnt3, 0);
}

TEST(IpAddress, Constexpr_strchr_array) {
    static constexpr char arr0[] = "0.0.0.0";
    constexpr auto *p0 = PCAP::PCAPStrUtils::strchr(arr0, '.');
    EXPECT_EQ(*p0, '.');

    static constexpr char arr1[] = "0.0.0.0";
    constexpr auto *p1 = PCAP::PCAPStrUtils::strchr(arr1, ':');
    EXPECT_EQ(p1, nullptr);

    static constexpr char arr2[] = "FF:FF:FF:FF:FF:FF";
    constexpr auto *p2 = PCAP::PCAPStrUtils::strchr(arr2, ':');
    EXPECT_EQ(*p2, ':');

    static constexpr char arr3[] = "FF:FF:FF:FF:FF:FF";
    constexpr auto *p3 = PCAP::PCAPStrUtils::strchr(arr3, '.');
    EXPECT_EQ(p3, nullptr);
}

TEST(IpAddress, Constexpr_strchr_ptr) {
    static constexpr const char *ptr0 = "0.0.0.0";
    constexpr auto *p0 = PCAP::PCAPStrUtils::strchr(ptr0, '.');
    EXPECT_EQ(*p0, '.');

    static constexpr const char *ptr1 = "0.0.0.0";
    constexpr auto *p1 = PCAP::PCAPStrUtils::strchr(ptr1, ':');
    EXPECT_EQ(p1, nullptr);

    static constexpr const char *ptr2 = "FF:FF:FF:FF:FF:FF";
    constexpr auto *p2 = PCAP::PCAPStrUtils::strchr(ptr2, ':');
    EXPECT_EQ(*p2, ':');

    static constexpr const char *ptr3 = "FF:FF:FF:FF:FF:FF";
    constexpr auto *p3 = PCAP::PCAPStrUtils::strchr(ptr3, '.');
    EXPECT_EQ(p3, nullptr);
}

TEST(IpAddress, Construct_using_ptr_and_size) {
    static const char arr[] = "192.168.1.1";
    constexpr PCAP::IpAddress a{arr, sizeof(arr)-1};
    PCAP::IpAddress b{std::string("192.168.1.1")};
    EXPECT_EQ(a, b);
    EXPECT_EQ(a.to_string(), b.to_string());
    EXPECT_EQ(a.to_long(), b.to_long());
    EXPECT_EQ(a, a & b);
    EXPECT_TRUE(memcmp(a.data(), b.data(), 4) == 0);
}

TEST(IpAddress, Construct_using_literals) {
    PCAP::IpAddress a{"192.168.1.1"};
    PCAP::IpAddress b{std::string("192.168.1.1")};
    EXPECT_EQ(a, b);
    EXPECT_EQ(a.to_string(), b.to_string());
    EXPECT_EQ(a.to_long(), b.to_long());
    EXPECT_EQ(a, a & b);
    EXPECT_TRUE(memcmp(a.data(), b.data(), 4) == 0);
}

TEST(IpAddress, Equal) {
    PCAP::IpAddress a(std::string("192.168.1.1"));
    PCAP::IpAddress b("192.168.1.1");
    EXPECT_EQ(a, b);
    EXPECT_EQ(a.to_string(), b.to_string());
    EXPECT_EQ(a.to_long(), b.to_long());
    EXPECT_EQ(a, a & b);
    EXPECT_TRUE(memcmp(a.data(), b.data(), 4) == 0);
}

TEST(IpAddress, NotEqual) {
    PCAP::IpAddress a("192.168.2.1");
    PCAP::IpAddress b(111234677);
    EXPECT_NE(a, b);
    EXPECT_NE(a.to_string(), b.to_string());
    EXPECT_NE(a.to_long(), b.to_long());
    EXPECT_NE(a, a & b);
    EXPECT_FALSE(memcmp(a.data(), b.data(), 4) == 0);
}

TEST(IpAddress, Default) {
    PCAP::IpAddress a;
    EXPECT_EQ(PCAP::IpAddress("255.255.255.255"), a);
}

TEST(IpAddress, Compare) {
    PCAP::IpAddress a("192.168.2.1");
    PCAP::IpAddress b("192.168.3.1");
    EXPECT_TRUE(a != b);
    EXPECT_FALSE(a == b);
    EXPECT_TRUE(a < b);
    EXPECT_FALSE(a > b);
}

TEST(IpAddress, Invalid) {
    EXPECT_THROW(PCAP::IpAddress("0"), std::runtime_error);
    EXPECT_THROW(PCAP::IpAddress("0:0:0:0"), std::runtime_error);
}

TEST(IpAddress, Stream) {
    PCAP::IpAddress ip("1.2.3.4");
    std::stringstream stream;
    stream << ip;
    EXPECT_EQ(ip.to_string(), stream.str());
}