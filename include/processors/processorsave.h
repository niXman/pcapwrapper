#ifndef PCAPPROCESSORSAVE_H
#define PCAPPROCESSORSAVE_H

#include <string>
#include <vector>
#include <mutex>
#include <utility>

#include "processorpolicy.h"

namespace PCAP {

class ProcessorSave : public ProcessorPolicy
{
public:
    virtual ~ProcessorSave() noexcept;

    bool save(const std::string& filename);
private:
    void callback_impl(const unsigned char *package, const pcap_pkthdr &header) override;

    std::mutex m_mutex;

    using Package = std::pair<pcap_pkthdr, unsigned char*>;
    std::vector<Package> m_packages;
};

}


#endif