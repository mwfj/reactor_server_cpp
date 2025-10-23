#pragma once
#include "common.h"
#include "net_server.h"

/**
 * This class is designed for simulating the specific feature
 * by calling the net server library that we make
 */

class ReactorServer
{
private:
    NetServer net_server_;
public:
    ReactorServer(const std::string&, const size_t);
    ~ReactorServer() = default;

    void Start();
    void Stop();

    void NewConnection(std::shared_ptr<ConnectionHandler>);
    void CloseConnecition(std::shared_ptr<ConnectionHandler>);
    void Error(std::shared_ptr<ConnectionHandler>);
    void ProcessMessage(std::shared_ptr<ConnectionHandler>, std::string&);
    void SendComplete(std::shared_ptr<ConnectionHandler>);
};