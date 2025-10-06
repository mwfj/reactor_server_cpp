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
        addr_.sin_addr.s_addr = inet_addr(_ip.c_str());
        addr_.sin_port = htons(static_cast<in_port_t>(_port));
    }
    InetAddr(const sockaddr_in _clientAddr) : addr_(_clientAddr){}

    const char *Ip() const {
        return inet_ntoa(addr_.sin_addr);
    }
    uint16_t Port() const {
        return ntohs(addr_.sin_port);
    }
    const sockaddr* Addr() const {
        return reinterpret_cast<const sockaddr*>(&addr_);
    }

    void SetAddr(sockaddr_in _clientAddr){
        addr_ = _clientAddr;
    }
};