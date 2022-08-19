#include "../../../include/network/addresses/ipaddress.h"

#include <cstring>
#include <stdexcept>

#include "../../../include/helpers/helper.h"

namespace PCAP {

bool operator==(const IpAddress &lhs, const IpAddress &rhs) noexcept {
    const auto &lr = lhs.m_ip.second;
    const auto &rr = rhs.m_ip.second;
    return lr == rr;
}

bool operator!=(const IpAddress &lhs, const IpAddress &rhs) noexcept {
    return !(lhs == rhs);
}

bool operator<(const IpAddress &lhs, const IpAddress &rhs) noexcept {
    return lhs.m_ip < rhs.m_ip;
}

bool operator>(const IpAddress &lhs, const IpAddress &rhs) noexcept {
    return lhs.m_ip > rhs.m_ip;
}

std::ostream &operator<<(std::ostream &stream, const IpAddress &rhs) {
    stream << rhs.to_string();
    return stream;
}

IpAddress operator&(const IpAddress &lhs, const IpAddress &rhs) noexcept {
    return IpAddress(lhs.to_long() & rhs.to_long());
}

std::string IpAddress::to_string() const {
    std::string result;
    for (size_t i = 0; i < ip_addr_len; ++i) {
        result.append(std::to_string(int(m_ip.second[i])));
        if (i != ip_addr_len - 1)
            result.append(".");
    }
    return result;
}

ulong IpAddress::to_long() const noexcept {
    return 0 | m_ip.second[0] << 24 | m_ip.second[1] << 16 | m_ip.second[2] << 8 | m_ip.second[3];
}

const uchar *IpAddress::data() const noexcept { return m_ip.second.data(); }
}