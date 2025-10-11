#include "server.h"


NetworkServer::NetworkServer(const std::string& _ip, int _port) : ip_addr_(_ip), port_(_port){}
void NetworkServer::set_running_state(bool status){
    is_running_ = status;
}

void NetworkServer::Start(){
    listen_conn_.reset(new ConnectionHandler());
    InetAddr addr(ip_addr_, port_);

    listen_conn_->SetReuseAddr(true);
    listen_conn_->SetTcpNoDelay(true);
    listen_conn_->SetReusePort(true);
    listen_conn_->SetKeepAlive(true);

    listen_conn_->Bind(addr);
    listen_conn_->Listen(MAX_CONNECTIONS);

    ep_ = std::shared_ptr<EpollHandler>(new EpollHandler());
    serv_ch_ = std::shared_ptr<Channel>(new Channel(ep_, listen_conn_->fd()));

    // Register callback for accepting new connections
    serv_ch_->SetReadCallBackFn(
        std::bind(&Channel::NewConnection, serv_ch_.get(), std::ref(*listen_conn_))
    );
    serv_ch_->EnableReadMode();

    // CRITICAL: Add server channel to EpollHandler's map so events are tracked
    ep_->AddChannel(serv_ch_);
}

void NetworkServer::Run(){
    set_running_state(true);

    while(is_running()){
        // Use 1000ms timeout instead of blocking indefinitely
        // This allows the server to check is_running() periodically
        channels_ = ep_->WaitForEvent(1000);

        // Process all active channels
        for(auto& ch : channels_) {
            try {
                ch->HandleEvent();
            } catch (const std::exception& e) {
                // Log error but continue serving other clients
                std::cerr << "[SERVER] Error handling event: " << e.what() << std::endl;
            }
        }
    }
}

void NetworkServer::Stop(){
    set_running_state(false);
}