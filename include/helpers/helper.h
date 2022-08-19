#ifndef PCAPHELPER_H
#define PCAPHELPER_H

#include <array>
#include <stdexcept>
#include <vector>
#include <type_traits>

#include <cassert>
#include <cstring>

#include "../network/addresses/ipaddress.h"
#include "../network/addresses/macaddress.h"
#include "../network/sniff/snifficmp.h"
#include "../network/sniff/sniffip.h"
#include "../network/sniff/snifftcp.h"
#include "../network/sniff/sniffudp.h"

namespace PCAP {
namespace PCAPHelper {

void set_ip_checksum(sniffip *ip);
void set_icmp_checksum(sniffip *ip, snifficmp *icmp);
void set_tcp_checksum(sniffip *ip, snifftcp *tcp, uchar *data);
void set_udp_checksum(sniffip *ip, sniffudp *udp, uchar *data);

bool setIp(PCAP::uchar *ip, const char *str, std::size_t len);
inline bool setIp(PCAP::uchar *ip, const std::string &ip_value)
{ return setIp(ip, ip_value.data(), ip_value.length()); }
template<std::size_t N>
bool setIp(PCAP::uchar *ip, const char (&str)[N])
{ return setIp(ip, str, N-1); }

bool setMac(PCAP::uchar *addr, const char *str, std::size_t len);
inline bool setMac(PCAP::uchar *addr, const std::string &ethernet_value)
{ return setMac(addr, ethernet_value.data(), ethernet_value.length()); }
template<std::size_t N>
bool setMac(PCAP::uchar *addr, const char (&str)[N])
{ return setMac(addr, str, N-1); }

PCAP::IpAddress get_ip(const std::string &interface);
PCAP::MacAddress get_mac(const std::string &interface);
PCAP::IpAddress get_mask(const std::string &interface);
PCAP::IpAddress get_router_ip(const std::string &inteface);
PCAP::IpAddress get_broadcast_ip(const std::string &inteface);
std::vector<PCAP::IpAddress> get_ips(const PCAP::IpAddress &local_ip,
                                    const PCAP::IpAddress &network_mask);
PCAP::MacAddress get_mac(const PCAP::IpAddress &target_ip,
                        const std::string &interface);

template<typename T>
ushort checksum(T *p, int count) {
    uint sum = 0;
    ushort *addr = (ushort *)p;

    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }

    if (count > 0)
        sum += *(uchar *)addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}
}
}

#endif // PCAPHELPER_H
