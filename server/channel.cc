#include "channel.h"

Channel::Channel(std::shared_ptr<Dispatcher> _dispatcher, int _fd) 
    : fd_(_fd), event_dispatcher_(_dispatcher){}

Channel::~Channel() {
    // Close the file descriptor if not already closed
    // Don't call close callback during destruction to avoid use-after-free
    if(!is_channel_closed_ && fd_ != -1){
        ::close(fd_);
        fd_ = -1;
    }
}

void Channel::EnableETMode(){
    if(is_channel_closed_) return;
    event_ |= EPOLLET;
}

void Channel::DisableETMode(){
    if(is_channel_closed_) return;
    event_ &= ~EPOLLET;
}

bool Channel::isEnableETMode() const {
    return (event_ & EPOLLET) == EPOLLET;
}

void Channel::EnableReadMode(){
    if(is_channel_closed_) return;
    event_ |= EPOLLIN;
    std::shared_ptr<Dispatcher> ep_shared = event_dispatcher_.lock();
    if(ep_shared)
        ep_shared -> UpdateChannel(shared_from_this());
}

void Channel::DisableReadMode(){
    if(is_channel_closed_) return;
    event_ &= ~EPOLLIN;
    std::shared_ptr<Dispatcher> ep_shared = event_dispatcher_.lock();
    if(ep_shared)
        ep_shared -> UpdateChannel(shared_from_this());
}

bool Channel::isEnableReadMode() const {
    return (event_ & EPOLLIN) == EPOLLIN;
}

void Channel::EnableWriteMode(){
    if(is_channel_closed_)  return ;
    event_ |= EPOLLOUT;
    std::shared_ptr<Dispatcher> ep_shared = event_dispatcher_.lock();
    if(ep_shared)
        ep_shared -> UpdateChannel(shared_from_this());
}

void Channel::DisableWriteMode(){
    if(is_channel_closed_)  return ;
    event_ &= ~EPOLLOUT;
    std::shared_ptr<Dispatcher> ep_shared = event_dispatcher_.lock();
    if(ep_shared)
        ep_shared -> UpdateChannel(shared_from_this());
}

bool Channel::isEnableWriteMode() const{
    return (event_ & EPOLLOUT) == EPOLLOUT;
}

void Channel::HandleEvent() {
    if(is_channel_closed_) {
        return;
    }

    const uint32_t events = devent_;

    // Handle close events with highest priority
    // If connection is closing, don't process other events
    if(events & (EPOLLRDHUP | EPOLLHUP)){
        if(close_fn_)
            close_fn_();
        return; // Don't process other events if closing
    }

    // Handle read events
    if(events & (EPOLLIN | EPOLLPRI)){
        // Call Acceptor::NewConnection if it is acceptor channel
        // Call ConnectionHandler::OnMessage if it is client channel
        if(read_fn_)
            read_fn_();
    }

    // Handle write events
    if(events & EPOLLOUT){
        if(write_fn_)
            write_fn_();
    }

    // Handle error events
    if(events & EPOLLERR){
        if(error_fn_)
            error_fn_();
    }
}


void Channel::SetReadCallBackFn(std::function<void()> fn){
    read_fn_ = fn;
}

void Channel::SetWriteCallBackFn(std::function<void()> fn){
    write_fn_ = fn;
}

void Channel::SetCloseCallBackFn(std::function<void()> fn){
    close_fn_ = fn;
}

void Channel::SetErrorCallBackFn(std::function<void()> fn){
    error_fn_ = fn;
}

void Channel::CloseChannel(){
    // Use atomic compare-and-swap to prevent race conditions
    // If already closed, return immediately
    bool expected = false;
    if (!is_channel_closed_.compare_exchange_strong(expected, true)) {
        // Another thread already closed this channel
        return;
    }

    // NOTE: Do NOT call close_fn_() here to avoid recursion
    // The close callback should call CloseChannel(), not the other way around

    // IMPORTANT: Remove fd from epoll BEFORE closing it
    // This prevents epoll fd reuse bugs when the OS reuses the fd number
    if(fd_ != -1 && is_epoll_in_){
        std::shared_ptr<Dispatcher> ep_shared = event_dispatcher_.lock();
        if(ep_shared){
            ep_shared->RemoveChannel(shared_from_this());
        }
    }

    if(fd_ != -1){
        ::close(fd_);
        fd_ = -1;
    }

    is_epoll_in_ = false;
    event_ = 0;
    devent_ = 0;
}
