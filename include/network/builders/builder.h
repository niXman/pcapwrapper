#ifndef BUILDER_H
#define BUILDER_H

#include <map>
#include <memory>

#include "../../helpers/common.h"
#include "../addresses/ipaddress.h"
#include "../addresses/macaddress.h"
#include "../packages/arppackage.h"
#include "../packages/icmppackage.h"
#include "../packages/tcppackage.h"
#include "../packages/udppackage.h"
#include "keys.h"

namespace PCAP {
namespace PCAPBuilder {

class Option {
  public:
    explicit Option(uint value) : m_value_int{value} {}

    explicit Option(ushort value) : m_value_short{value} {}

    explicit Option(uchar value) : m_value_char{value} {}

    explicit Option(PCAP::IpAddress ip) : m_value_ip{ip} {}

    explicit Option(PCAP::MacAddress mac) : m_value_mac{mac} {}

    Option(const Option &rhs) noexcept = default;
    Option &operator=(const Option &rhs) noexcept = default;
    Option(Option &&rhs) noexcept = default;
    Option &operator=(Option &&rhs) noexcept = default;

    const MacAddress& get_mac() const { return m_value_mac; }
    const IpAddress& get_ip() const { return m_value_ip; }
    const uchar& get_char() const { return m_value_char; }
    const ushort& get_short() const { return m_value_short; }
    const uint& get_int() const { return m_value_int; }

    using keyval_map = std::map<Keys, Option>;

    friend void set_ethernet(ARPPackage &package, const keyval_map &options);
    friend void set_ethernet(UDPPackage &package, const keyval_map &options);
    friend void set_ethernet(ICMPPackage &package, const keyval_map &options);
    friend void set_ethernet(TCPPackage &package, const keyval_map &options);

    friend void set_ip(UDPPackage &package, const keyval_map &options);
    friend void set_ip(TCPPackage &package, const keyval_map &options);
    friend void set_ip(ICMPPackage &package, const keyval_map &options);

    friend void set_udp(UDPPackage &package, const keyval_map &options);

    friend void set_icmp(ICMPPackage &package, const keyval_map &options);

    friend void set_tcp(TCPPackage &package, const keyval_map &options);

    friend void set_arp(ARPPackage &package, const keyval_map &options);

  private:
    union {
        uint m_value_int;
        ushort m_value_short;
        uchar m_value_char;
        PCAP::IpAddress m_value_ip;
        PCAP::MacAddress m_value_mac;
    };
};

ARPPackage make_arp(const Option::keyval_map &options);
UDPPackage make_udp(const Option::keyval_map &options);
ICMPPackage make_icmp(const Option::keyval_map &options);
TCPPackage make_tcp(const Option::keyval_map &options);

}
}

#endif // BUILDER_H
