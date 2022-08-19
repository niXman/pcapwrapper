#include "../../../include/network/builders/builder.h"

#include <netinet/in.h>

#include "../../../include/network/addresses/ipaddress.h"
#include "../../../include/network/addresses/macaddress.h"

#include <cassert>

namespace PCAP {
namespace PCAPBuilder {

static uchar package_buffer[snap_len] = {};

template<typename T>
void set_ethernet_impl(T &package, const Option::keyval_map &options) {
    for (auto &option : options) {
        switch ( option.first ) {
            case Keys::Key_Eth_Mac_Src: package.set_src_mac(option.second.get_mac()); break;
            case Keys::Key_Eth_Mac_Dst: package.set_dst_mac(option.second.get_mac()); break;
            default: break;
        }
    }
}

void set_ethernet(ARPPackage &package, const Option::keyval_map &options) {
    return set_ethernet_impl(package, options);
}

void set_ethernet(UDPPackage &package, const Option::keyval_map &options) {
    return set_ethernet_impl(package, options);
}

void set_ethernet(ICMPPackage &package, const Option::keyval_map &options) {
    return set_ethernet_impl(package, options);
}

void set_ethernet(TCPPackage &package, const Option::keyval_map &options) {
    return set_ethernet_impl(package, options);
}

template<typename T>
void set_ip_impl(T &package, const Option::keyval_map &options) {
    for (auto &option : options) {
        switch ( option.first ) {
            case Keys::Key_Ip_Src: package.set_src_ip(option.second.get_ip()); break;
            case Keys::Key_Ip_Dst: package.set_dst_ip(option.second.get_ip()); break;
            case Keys::Key_Ip_TTL: package.set_ttl(option.second.get_char()); break;
            case Keys::Key_Ip_Flags: package.set_ip_flags(option.second.get_char()); break;
            case Keys::Key_Ip_Id: package.set_id(option.second.get_short()); break;
            case Keys::Key_Ip_Length: package.set_total_length(option.second.get_short()); break;
            default: break;
        }
    }
}

void set_ip(UDPPackage &package, const Option::keyval_map &options) {
    return set_ip_impl(package, options);
}

void set_ip(TCPPackage &package, const Option::keyval_map &options) {
    return set_ip_impl(package, options);
}

void set_ip(ICMPPackage &package, const Option::keyval_map &options) {
    return set_ip_impl(package, options);
}

void set_udp(UDPPackage &package, const Option::keyval_map &options) {
    for (auto &option : options) {
        switch ( option.first ) {
            case Keys::Key_Udp_Length: package.set_udp_length(option.second.m_value_short); break;
            case Keys::Key_Src_Port: package.set_src_port(option.second.m_value_short); break;
            case Keys::Key_Dst_Port: package.set_dst_port(option.second.m_value_short); break;
            default: break;
        }
    }
}

void set_icmp(ICMPPackage &package, const Option::keyval_map &options) {
    for (auto &option : options) {
        switch ( option.first ) {
            case Keys::Key_Icmp_Type: package.set_type(option.second.m_value_char); break;
            case Keys::Key_Icmp_Code: package.set_code(option.second.m_value_char); break;
            default: break;
        }
    }
}

void set_tcp(TCPPackage &package, const Option::keyval_map &options) {
    for (auto &option : options) {
        switch ( option.first ) {
            case Keys::Key_Src_Port: package.set_src_port(option.second.m_value_short); break;
            case Keys::Key_Dst_Port: package.set_dst_port(option.second.m_value_short); break;
            case Keys::Key_Tcp_SeqNr: package.set_seq_nr(option.second.m_value_int); break;
            case Keys::Key_Tcp_AckNr: package.set_ack_nr(option.second.m_value_int); break;
            case Keys::Key_Tcp_Flags: package.set_tcp_flags(option.second.m_value_char); break;
            default: break;
        }
    }
}

void set_arp(ARPPackage &package, const Option::keyval_map &options) {
    for (auto &option : options) {
        switch ( option.first ) {
            case Keys::Key_Arp_Mac_Src: package.set_src_arp_mac(option.second.m_value_mac); break;
            case Keys::Key_Arp_Mac_Dst: package.set_dst_arp_mac(option.second.m_value_mac); break;
            case Keys::Key_Arp_Opcode: package.set_opcode(option.second.m_value_char); break;
            case Keys::Key_Ip_Src: package.set_src_ip(option.second.get_ip()); break;
            case Keys::Key_Ip_Dst: package.set_dst_ip(option.second.get_ip()); break;
            default: break;
        }
    }
}

PCAP::ARPPackage make_arp(const Option::keyval_map &options) {
    PCAP::ARPPackage package(package_buffer, snap_len, true);
    package.set_src_mac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.set_dst_mac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.set_ether_type(0x0806);
    package.set_hardware_type(0x01);
    package.set_protocol(0x0800);
    package.set_hardware_length(0x06);
    package.set_protocol_length(0x04);
    package.set_opcode(0x01);
    package.set_src_arp_mac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.set_src_ip(IpAddress("255.255.255.255"));
    package.set_dst_arp_mac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.set_dst_ip(IpAddress("255.255.255.255"));

    set_ethernet(package, options);
    set_arp(package, options);

    return package;
}

PCAP::UDPPackage make_udp(const Option::keyval_map &options) {
    PCAP::UDPPackage package(package_buffer, snap_len, true);
    package.set_src_mac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.set_dst_mac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.set_ether_type(0x0800);
    package.set_vhl(0x45);
    package.set_tos(0x0);
    package.set_total_length(0x001c);
    package.set_id(0x1000);
    package.set_ip_flags(0x0);
    package.set_fragment_offset(0x0);
    package.set_ttl(0x64);
    package.set_protocol(0x11);
    package.set_src_ip(IpAddress("255.255.255.255"));
    package.set_dst_ip(IpAddress("255.255.255.255"));
    package.set_src_port(1);
    package.set_dst_port(1);
    package.set_udp_length(0x0008);

    set_ethernet(package, options);
    set_ip(package, options);
    set_udp(package, options);

    return package;
}

ICMPPackage make_icmp(const Option::keyval_map &options) {
    PCAP::ICMPPackage package(package_buffer, snap_len, true);
    package.set_src_mac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.set_dst_mac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.set_ether_type(0x0800);
    package.set_vhl(0x45);
    package.set_tos(0x0);
    package.set_total_length(0x001c);
    package.set_id(0x1000);
    package.set_ip_flags(0x0);
    package.set_fragment_offset(0x0);
    package.set_ttl(0x64);
    package.set_protocol(0x01);
    package.set_src_ip(IpAddress("255.255.255.255"));
    package.set_dst_ip(IpAddress("255.255.255.255"));
    package.set_type(0x08);
    package.set_code(0x00);

    set_ethernet(package, options);
    set_ip(package, options);
    set_icmp(package, options);

    return package;
}

TCPPackage make_tcp(const Option::keyval_map &options) {
    PCAP::TCPPackage package(package_buffer, snap_len, true);
    package.set_src_mac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.set_dst_mac(MacAddress("FF:FF:FF:FF:FF:FF"));
    package.set_ether_type(0x0800);
    package.set_vhl(0x45);
    package.set_tos(0x0);
    package.set_total_length(0x0028);
    package.set_id(0x1000);
    package.set_ip_flags(0x0);
    package.set_fragment_offset(0x0);
    package.set_ttl(0x64);
    package.set_protocol(0x06);
    package.set_src_ip(IpAddress("255.255.255.255"));
    package.set_dst_ip(IpAddress("255.255.255.255"));
    package.set_src_port(1);
    package.set_dst_port(1);
    package.set_seq_nr(0x3323);
    package.set_ack_nr(0);
    package.set_data_offset(0x50);
    package.set_tcp_flags(0x02);
    package.set_window_size(0x7210);
    package.set_urgent_ptr(0x0000);

    set_ethernet(package, options);
    set_ip(package, options);
    set_tcp(package, options);

    return package;
}
}
}
