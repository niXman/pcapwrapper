#include "../../../include/network/addresses/macaddress.h"

#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include "../../../include/helpers/helper.h"

namespace PCAP {

MacAddress::MacAddress(const char *mac, std::size_t len)
    :m_mac{PCAP::PCAPStrUtils::parse_mac_addr(mac, len)}
{
    if ( !m_mac.first )
        throw std::runtime_error("Wrong argument");
}

MacAddress::MacAddress(uchar *data)
    :m_mac{true, {}}
{
    std::memcpy(m_mac.second.data(), data, ethernet_addr_len);
}

MacAddress::MacAddress() { std::memset(m_mac.second.data(), 0xFF, ethernet_addr_len); }

bool operator==(const MacAddress &lhs, const MacAddress &rhs) noexcept {
    return lhs.m_mac.second == rhs.m_mac.second;
}

bool operator!=(const MacAddress &lhs, const MacAddress &rhs) noexcept {
    return !(lhs.m_mac == rhs.m_mac);
}

std::ostream &operator<<(std::ostream &stream, const MacAddress &rhs) {
    stream << rhs.to_string();
    return stream;
}

std::string MacAddress::to_string() const {
    std::stringstream stream;
    for (size_t i = 0; i < ethernet_addr_len; ++i) {
        stream << std::hex << std::uppercase << int(m_mac.second[i]);
        if (i != ethernet_addr_len - 1)
            stream << ":";
    }
    return stream.str();
}

const uchar *MacAddress::data() const noexcept { return m_mac.second.data(); }

} // ns PCAP