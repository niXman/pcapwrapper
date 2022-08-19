#ifndef PCAPIPADDRESS_H
#define PCAPIPADDRESS_H

#include "../../helpers/common.h"
#include "../../helpers/constants.h"
#include "../../helpers/strutils.h"
#include <array>
#include <ostream>
#include <string>

namespace PCAP {

class IpAddress {
  public:
    explicit constexpr IpAddress(const char *ip, std::size_t len)
        :m_ip{PCAPStrUtils::parse_ip_addr(ip, len)}
    {
        if ( !m_ip.first )
            throw std::runtime_error("Wrong argument");
    }
    template<std::size_t N>
    explicit constexpr IpAddress(const char (&ip)[N])
        :IpAddress{ip, N-1}
    {}
    explicit IpAddress(const std::string &ip)
        :IpAddress{ip.data(), ip.length()}
    {}
    explicit constexpr IpAddress(uchar *data) noexcept
        :m_ip{{true}, {data[0], data[1], data[2], data[3]}}
    {}
    explicit constexpr IpAddress(ulong ip) noexcept
        :m_ip{
             {true}
            ,{(uchar)(ip >> 24 & 0xFF)
            ,(uchar)(ip >> 16 & 0xFF)
            ,(uchar)(ip >> 8 & 0xFF)
            ,(uchar)(ip & 0xFF)
        }}
    {}

    explicit constexpr IpAddress()
        :m_ip{{false}, {0xFF, 0xFF, 0xFF, 0xFF}}
    {}

    IpAddress(const IpAddress &rhs) noexcept = default;
    IpAddress(IpAddress &&rhs) noexcept = default;
    IpAddress &operator=(const IpAddress &) noexcept = default;
    IpAddress &operator=(IpAddress &&) noexcept = default;

    friend bool operator==(const IpAddress &lhs, const IpAddress &rhs) noexcept;
    friend bool operator!=(const IpAddress &lhs, const IpAddress &rhs) noexcept;
    friend bool operator<(const IpAddress &lhs, const IpAddress &rhs) noexcept;
    friend bool operator>(const IpAddress &lhs, const IpAddress &rhs) noexcept;
    friend std::ostream &operator<<(std::ostream &stream, const IpAddress &rhs);
    friend IpAddress operator&(const IpAddress &lhs,
                               const IpAddress &rhs) noexcept;

    std::string to_string() const;
    ulong to_long() const noexcept;
    const uchar *data() const noexcept;

  private:
    std::pair<bool, std::array<uchar, ip_addr_len>> m_ip;
};
}

#endif