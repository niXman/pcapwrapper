#ifndef PCAPCOMMON_H
#define PCAPCOMMON_H

namespace PCAP {

using uchar = unsigned char;
using ushort = unsigned short;
using uint = unsigned int;
using ulong = unsigned long;

} // ns PCAP

#if __cplusplus >= 201402L
#   define PCAP_CXX14_CONSTEXPR constexpr
#else
#   define PCAP_CXX14_CONSTEXPR
#endif // __cplusplus >= 201402L

#if __cplusplus >= 201703L
#   define PCAP_FALLTHROUGH [[fallthrough]]
#else
#   if defined(__clang__)
#       define PCAP_FALLTHROUGH [[clang::fallthrough]]
#   elif defined(__GNUC__)
#       define PCAP_FALLTHROUGH __attribute__ ((fallthrough))
#   elif defined(_MSC_VER)
#       define PCAP_FALLTHROUGH
#   else
#       error "Unknown compiler"
#   endif // if defined(__clang__)
#endif // __cplusplus >= 201703L

#endif // PCAPCOMMON_H
