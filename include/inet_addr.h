#pragma once
#include "common.h"

class InetAddr{
private:
    sockaddr_in addr_; 
public:
    InetAddr() = default;
    ~InetAddr() = default;
    InetAddr(const std::string& _ip, int _port){
        memset(&addr_, 0, sizeof addr_);
        addr_.sin_family = AF_INET;
        // Use inet_pton (not inet_addr) to reject legacy shorthand/octal forms
        // like "1" (→ 0.0.0.1) or "0127.0.0.1" (→ 87.0.0.1). Only strict
        // dotted-quad notation is accepted, consistent with ConfigLoader::Validate.
        if (inet_pton(AF_INET, _ip.c_str(), &addr_.sin_addr) != 1) {
            addr_.sin_addr.s_addr = INADDR_NONE;
        }
        addr_.sin_port = htons(static_cast<in_port_t>(_port));
    }
    InetAddr(const sockaddr_in _clientAddr) : addr_(_clientAddr){}

    const char *Ip() const {
        return inet_ntoa(addr_.sin_addr);
    }
    size_t Port() const {
        return ntohs(addr_.sin_port);
    }
    const sockaddr* Addr() const {
        return reinterpret_cast<const sockaddr*>(&addr_);
    }

    void SetAddr(sockaddr_in _clientAddr){
        addr_ = _clientAddr;
    }
};