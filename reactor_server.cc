#include "reactor_server.h"
#include <iostream>


ReactorServer::ReactorServer(const std::string& _ip, const size_t _port)
    : net_server_(_ip, _port)
{
    net_server_.SetNewConnectionCb(std::bind(&ReactorServer::NewConnection, this, std::placeholders::_1));
    net_server_.SetCloseConnectionCb(std::bind(&ReactorServer::CloseConnecition, this, std::placeholders::_1));
    net_server_.SetErrorCb(std::bind(&ReactorServer::CloseConnecition, this, std::placeholders::_1));
    net_server_.SetOnMessageCb(std::bind(&ReactorServer::ProcessMessage, this, std::placeholders::_1, std::placeholders::_2));
    net_server_.SetSendCompletionCb(std::bind(&ReactorServer::SendComplete, this, std::placeholders::_1));
}

void ReactorServer::Start(){
    net_server_.Start();
}

void ReactorServer::Stop(){
    net_server_.Stop();
}

void ReactorServer::NewConnection(std::shared_ptr<ConnectionHandler> conn){
    std::cout << "New Connection Comes In" << std::endl;
    // Can add some extra features related code below
}

void ReactorServer::CloseConnecition(std::shared_ptr<ConnectionHandler> conn){
    std::cout << "Connection Closed" << std::endl;
    // Can add some extra features related code below
}

void ReactorServer::Error(std::shared_ptr<ConnectionHandler> conn){
    std::cout << "Error Function Called" << std::endl;
    // Can add some extra features related code below
}

void ReactorServer::ProcessMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message){
    std::cout << "Process Message" << message << std::endl;
    // Can add some extra features related code below
    // Here we are just simple echo that message
    message = "[Server Reply]: " + message;
    conn -> SendData(message.data(), message.size());
}

void ReactorServer::SendComplete(std::shared_ptr<ConnectionHandler> conn){
    std::cout << "Message Send Completed" << std::endl;
    // Can add some feature related code below
}
