
#ifndef PCAPWRAPPER_STRUTILS_H
#define PCAPWRAPPER_STRUTILS_H

#include "common.h"

#include <array>
#include <string>
#include <type_traits>
#include <cstdint>

namespace PCAP {
namespace PCAPStrUtils {

PCAP_CXX14_CONSTEXPR uchar hex2uchar(const char *str) {
    const char l = str[0];
    const char r = str[1];

    uchar a = (l <= '9') ? l - '0' : (l & 0x7) + 9;
    uchar b = (r <= '9') ? r - '0' : (r & 0x7) + 9;

    return (a << 4) + b;
}

template<std::size_t N>
PCAP_CXX14_CONSTEXPR std::size_t strcnt(const char (&str)[N], char ch) {
    auto cnt = 0u;
    for ( const char *p = str; *p; ++p ) {
        cnt += static_cast<::uint>(*p == ch);
    }

    return cnt;
}

template<typename ConstCharPtr>
PCAP_CXX14_CONSTEXPR typename std::enable_if<
    std::is_same<ConstCharPtr, const char *>::value
    ,ConstCharPtr
    >::type
strchr(ConstCharPtr s, char c) {
    for ( ; (*s) && ((*s) != c); ++s )
        ;

    return (*s) ? s : nullptr;
}

template<std::size_t N>
PCAP_CXX14_CONSTEXPR const char* strchr(const char (&s)[N], char c) {
    auto i = 0u;
    for ( ; s[i] != 0 && s[i] != c; ++i )
        ;

    return (s[i] != 0) ? s + i : nullptr;
}

PCAP_CXX14_CONSTEXPR std::uint64_t atou64(const char *ptr, std::size_t len) {
    const auto *str = (const std::uint8_t *)ptr;
    std::uint64_t v = 0;
    switch ( len ) {
    case 20: v = v + (str[len - 20] - '0') * 10000000000000000000ull; PCAP_FALLTHROUGH;
    case 19: v = v + (str[len - 19] - '0') * 1000000000000000000ull; PCAP_FALLTHROUGH;
    case 18: v = v + (str[len - 18] - '0') * 100000000000000000ull; PCAP_FALLTHROUGH;
    case 17: v = v + (str[len - 17] - '0') * 10000000000000000ull; PCAP_FALLTHROUGH;
    case 16: v = v + (str[len - 16] - '0') * 1000000000000000ull; PCAP_FALLTHROUGH;
    case 15: v = v + (str[len - 15] - '0') * 100000000000000ull; PCAP_FALLTHROUGH;
    case 14: v = v + (str[len - 14] - '0') * 10000000000000ull; PCAP_FALLTHROUGH;
    case 13: v = v + (str[len - 13] - '0') * 1000000000000ull; PCAP_FALLTHROUGH;
    case 12: v = v + (str[len - 12] - '0') * 100000000000ull; PCAP_FALLTHROUGH;
    case 11: v = v + (str[len - 11] - '0') * 10000000000ull; PCAP_FALLTHROUGH;
    case 10: v = v + (str[len - 10] - '0') * 1000000000ull; PCAP_FALLTHROUGH;
    case 9 : v = v + (str[len - 9 ] - '0') * 100000000ull; PCAP_FALLTHROUGH;
    case 8 : v = v + (str[len - 8 ] - '0') * 10000000ull; PCAP_FALLTHROUGH;
    case 7 : v = v + (str[len - 7 ] - '0') * 1000000ull; PCAP_FALLTHROUGH;
    case 6 : v = v + (str[len - 6 ] - '0') * 100000ull; PCAP_FALLTHROUGH;
    case 5 : v = v + (str[len - 5 ] - '0') * 10000ull; PCAP_FALLTHROUGH;
    case 4 : v = v + (str[len - 4 ] - '0') * 1000ull; PCAP_FALLTHROUGH;
    case 3 : v = v + (str[len - 3 ] - '0') * 100ull; PCAP_FALLTHROUGH;
    case 2 : v = v + (str[len - 2 ] - '0') * 10ull; PCAP_FALLTHROUGH;
    case 1 : v = v + (str[len - 1 ] - '0') * 1ull; PCAP_FALLTHROUGH;
    default: break;
    }

    return v;
}

PCAP_CXX14_CONSTEXPR std::pair<bool, std::array<uchar, ethernet_addr_len>>
parse_mac_addr(const char *s, std::size_t slen) {
    std::array<uchar, ethernet_addr_len> res{};
    if ( slen != 17 ) {
        return {false, res};
    }

    res[0] = hex2uchar(s+ 0);
    res[1] = hex2uchar(s+ 3);
    res[2] = hex2uchar(s+ 6);
    res[3] = hex2uchar(s+ 9);
    res[4] = hex2uchar(s+12);
    res[5] = hex2uchar(s+15);

    return {true, res};
}

template<std::size_t Ch>
PCAP_CXX14_CONSTEXPR std::pair<bool, std::array<uchar, ethernet_addr_len>>
parse_mac_addr(const char (&str)[Ch]) {
    static_assert(Ch-1 == 6*2+5, ""); // "FF:FF:FF:FF:FF:FF"
    static_assert(PCAP::PCAPStrUtils::strcnt(str, ':') == 5, "");
    static_assert(str[ 2] == ':', "");
    static_assert(str[ 5] == ':', "");
    static_assert(str[ 8] == ':', "");
    static_assert(str[11] == ':', "");
    static_assert(str[14] == ':', "");

    return parse_mac_addr(str, Ch-1);
}

PCAP_CXX14_CONSTEXPR std::pair<bool, std::array<uchar, ip_addr_len>>
parse_ip_addr(const char *s, std::size_t slen) {
    std::array<uchar, ip_addr_len> res{};
    if ( (slen < 7) || (slen > 15) ) {
        return {false, res};
    }
    constexpr char sep = '.';
    const auto *sstart = s;
    auto *dst = &res[0];
    const auto *dstart = dst;
    const char *current = PCAP::PCAPStrUtils::strchr(s, sep);
    if ( !current ) {
        return {false, res};
    }

    for ( ; current; current = PCAP::PCAPStrUtils::strchr(s, sep) ) {
        std::size_t len = current - s;
        *dst++ = PCAP::PCAPStrUtils::atou64(s, len);

        s = current + 1;
    }

    if ( dst != (dstart + 3) ) {
        return {false, res};
    }

    std::size_t len = slen - (s - sstart);
    *dst = PCAP::PCAPStrUtils::atou64(s, len);

    return {true, res};
}

template<std::size_t Ch>
PCAP_CXX14_CONSTEXPR std::pair<bool, std::array<uchar, ip_addr_len>>
parse_ip_addr(std::size_t dst_len, const char (&str)[Ch]) {
    static_assert(Ch-1 >= 7 && Ch-1 <= 15, "");
    static_assert(PCAP::PCAPStrUtils::strcnt(str, '.') == 3, "");

    return parse_ip_addr(str, Ch-1);
}

} // ns PCAPStrUtils
} // ns PCAP

#endif // PCAPWRAPPER_STRUTILS_H
