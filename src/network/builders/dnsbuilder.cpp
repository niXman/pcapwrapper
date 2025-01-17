#include "../../../include/network/builders/dnsbuilder.h"

#include "../../../include/helpers/helper.h"
#include "../../../include/helpers/strutils.h"
#include <array>
#include <cstring>
#include <netinet/in.h>

namespace PCAP {
namespace PCAPBuilder {

bool setIp(PCAP::uchar *ip, const std::string &ip_value) {
    auto pair = PCAP::PCAPStrUtils::parse_ip_addr(
         ip_value.data()
        ,ip_value.length()
    );
    if ( pair.first ) {
        memcpy(ip, pair.second.data(), ip_addr_len);
    }
    return pair.first;
}

// bool setMac(PCAP::uchar *addr, const std::string &ethernet_value, int base) {
//     std::array<PCAP::uchar, ethernet_addr_len> array;
//     bool sucessful =
//         PCAP::PCAPHelper::split_string<PCAP::uchar, ethernet_addr_len>(
//             ethernet_value, ':', array, base);
//     if (sucessful) {
//         memcpy(addr, array.data(), ethernet_addr_len);
//     }
//     return sucessful;
// }

PCAP::sniffdns_question
create_dns_question(ushort answers, const PCAP::uchar *data, ushort size) {
    PCAP::sniffdns_question question;
    memcpy(&question, data, size);
    question.m_flags = htons(0x8180);
    question.m_answers = htons(answers);
    return question;
}

PCAP::sniffdns_query create_dns_query(const PCAP::uchar *website) {
    PCAP::sniffdns_query query;
    query.m_query = (PCAP::uchar *)website;
    query.m_type = htons(0x0001);
    query.m_class = htons(0x0001);
    return query;
}

PCAP::sniffdns_answer create_dns_answer(const std::string &spoof_ip) {
    PCAP::sniffdns_answer answer;
    answer.m_name = htons(0xc00c);
    answer.m_type = htons(0x0001);
    answer.m_class = htons(0x0001);
    answer.m_time_to_live[0] = 0x00;
    answer.m_time_to_live[1] = 0x00;
    answer.m_time_to_live[2] = 0x00;
    answer.m_time_to_live[3] = 0x18;
    answer.data_length = htons(0x0004);
    setIp(answer.m_address, spoof_ip);
    return answer;
}

DNSBuilder::DNSBuilder() : m_index{0} { memset(m_package, '\0', snap_len); }

void DNSBuilder::operator<<(PCAP::sniffethernet ethernet) {
    memcpy(m_package, &ethernet, sizeof(ethernet));
    m_index += sizeof(ethernet);
    m_ip = (PCAP::sniffip *)&m_package[m_index];
}

void DNSBuilder::operator<<(PCAP::sniffip ip) {
    memcpy(&m_package[m_index], &ip, sizeof(ip));
    m_index += sizeof(ip);
    m_udp = (PCAP::sniffudp *)&m_package[m_index];
}

void DNSBuilder::operator<<(PCAP::sniffudp udp) {
    memcpy(&m_package[m_index], &udp, sizeof(udp));
    m_index += sizeof(udp);
    m_question = (sniffdns_question *)&m_package[m_index];

    this->m_ip->m_ip_len = htons(ntohs(this->m_ip->m_ip_len) + sizeof(udp));
}

void DNSBuilder::operator<<(sniffdns_question question) {
    memcpy(&m_package[m_index], &question, sizeof(question));
    m_index += sizeof(question);
    m_query = (sniffdns_query *)&m_package[m_index];

    this->m_ip->m_ip_len =
        htons(ntohs(this->m_ip->m_ip_len) + sizeof(question));
    this->m_udp->m_length =
        htons(ntohs(this->m_udp->m_length) + sizeof(question));
}

void DNSBuilder::operator<<(sniffdns_query query) {
    memcpy(&m_package[m_index], query.m_query, strlen((char *)query.m_query));
    m_index += strlen((char *)query.m_query) + 1;
    memcpy(&m_package[m_index], &query.m_type, 2);
    m_index += 2;
    memcpy(&m_package[m_index], &query.m_class, 2);
    m_index += 2;
    m_answer = (sniffdns_answer *)&m_package[m_index];

    this->m_ip->m_ip_len =
        htons(ntohs(this->m_ip->m_ip_len) + strlen((char *)query.m_query) + 5);
    this->m_udp->m_length =
        htons(ntohs(this->m_udp->m_length) + strlen((char *)query.m_query) + 5);
}

void DNSBuilder::operator<<(sniffdns_answer answer) {
    memcpy(&m_package[m_index], &answer, sizeof(answer));
    m_index += sizeof(answer);

    this->m_ip->m_ip_len = htons(ntohs(this->m_ip->m_ip_len) + sizeof(answer));
    this->m_udp->m_length =
        htons(ntohs(this->m_udp->m_length) + sizeof(answer));
}

void DNSBuilder::build() {
    PCAP::PCAPHelper::set_ip_checksum(m_ip);
    PCAP::PCAPHelper::set_udp_checksum(m_ip, m_udp, (PCAP::uchar *)m_question);
}

PCAP::uchar *DNSBuilder::get_package() const {
    return (PCAP::uchar *)&m_package[0];
}

uint DNSBuilder::get_length() const { return m_index; }
}
}