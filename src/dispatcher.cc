#include "dispatcher.h"
#include "channel.h"

Dispatcher::Dispatcher() : ep_(std::unique_ptr<EpollHandler>(new EpollHandler())){}

void Dispatcher::set_running_state(bool status){
    is_running_ = status;
}

void Dispatcher::RunEventLoop(){
    set_running_state(true);

    while(is_running()){
        // Use 1000ms timeout instead of blocking indefinitely
        // This allows the server to check is_running() periodically
        std::vector<std::shared_ptr<Channel>> channels = ep_->WaitForEvent(1000);

        // Process all active channels
        for(auto& ch : channels) {
            try {
                ch->HandleEvent();
            } catch (const std::exception& e) {
                // Log error but continue serving other clients
                std::cerr << "[Dispatcher] Error handling event: " << e.what() << std::endl;
            }
        }
    }
}

void Dispatcher::StopEventLoop(){
    set_running_state(false);
}

void Dispatcher::UpdateChannel(std::shared_ptr<Channel> ch){
    ep_->UpdateEvent(ch);
}