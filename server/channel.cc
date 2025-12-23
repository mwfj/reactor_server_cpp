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
    event_ |= EVENT_ET;
}

void Channel::DisableETMode(){
    if(is_channel_closed_) return;
    event_ &= ~EVENT_ET;
}

bool Channel::isEnableETMode() const {
    return (event_ & EVENT_ET) == EVENT_ET;
}

void Channel::EnableReadMode(){
    if(is_channel_closed_) return;
    // IMPORTANT: EVENT_RDHUP must be explicitly requested to detect peer shutdown
    // Without it, we won't get notified when client closes the connection
    event_ |= (EVENT_READ | EVENT_RDHUP);
    std::shared_ptr<Dispatcher> ep_shared = event_dispatcher_.lock();
    if(ep_shared)
        ep_shared -> UpdateChannel(shared_from_this());
}

void Channel::DisableReadMode(){
    if(is_channel_closed_) return;
    event_ &= ~EVENT_READ;
    std::shared_ptr<Dispatcher> ep_shared = event_dispatcher_.lock();
    if(ep_shared)
        ep_shared -> UpdateChannel(shared_from_this());
}

bool Channel::isEnableReadMode() const {
    return (event_ & EVENT_READ) == EVENT_READ;
}

void Channel::EnableWriteMode(){
    if(is_channel_closed_)  return ;
    event_ |= EVENT_WRITE;
    std::shared_ptr<Dispatcher> ep_shared = event_dispatcher_.lock();
    if(ep_shared)
        ep_shared -> UpdateChannel(shared_from_this());
}

void Channel::DisableWriteMode(){
    if(is_channel_closed_)  return ;
    event_ &= ~EVENT_WRITE;
    std::shared_ptr<Dispatcher> ep_shared = event_dispatcher_.lock();
    if(ep_shared)
        ep_shared -> UpdateChannel(shared_from_this());
}

bool Channel::isEnableWriteMode() const{
    return (event_ & EVENT_WRITE) == EVENT_WRITE;
}

void Channel::HandleEvent() {
    if(is_channel_closed_) {
        return;
    }

    const uint32_t events = devent_;

    // Handle close events with highest priority
    // If connection is closing, don't process other events
    if(events & (EVENT_RDHUP | EVENT_HUP)){
        if(callbacks_.close_callback)
            callbacks_.close_callback();
        CloseChannel();
        return; // Don't process other events if closing
    }

    // Handle read events
    if(events & (EVENT_READ | EVENT_PRI)){
        // Call Acceptor::NewConnection if it is acceptor channel
        // Call ConnectionHandler::OnMessage if it is client channel
        if(callbacks_.read_callback)
            callbacks_.read_callback();
    }

    // Handle write events
    if(events & EVENT_WRITE){
        if(callbacks_.write_callback)
            callbacks_.write_callback();
    }

    // Handle error events
    if(events & EVENT_ERR){
        if(callbacks_.error_callback)
            callbacks_.error_callback();
    }
}

void Channel::SetReadCallBackFn(CALLBACKS_NAMESPACE::ChannelReadCallback fn){
    callbacks_.read_callback = std::move(fn);
}

void Channel::SetWriteCallBackFn(CALLBACKS_NAMESPACE::ChannelWriteCallback fn){
    callbacks_.write_callback = std::move(fn);
}

void Channel::SetCloseCallBackFn(CALLBACKS_NAMESPACE::ChannelCloseCallback fn){
    callbacks_.close_callback = std::move(fn);
}

void Channel::SetErrorCallBackFn(CALLBACKS_NAMESPACE::ChannelErrorCallback fn){
    callbacks_.error_callback = std::move(fn);
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
    if(fd_ != -1 && is_read_event_){
        std::shared_ptr<Dispatcher> ep_shared = event_dispatcher_.lock();
        if(ep_shared){
            ep_shared->RemoveChannel(shared_from_this());
        }
    }

    if(fd_ != -1){
        ::close(fd_);
        fd_ = -1;
    }

    is_read_event_ = false;
    event_ = 0;
    devent_ = 0;
}
