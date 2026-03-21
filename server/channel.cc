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

    // Handle read events BEFORE close events.
    // When RDHUP arrives with EVENT_READ (client sends final bytes then closes),
    // we must read the pending data first. ConnectionHandler::OnMessage() handles
    // EOF (read==0) by dispatching buffered data then closing.
    if(events & (EVENT_READ | EVENT_PRI)){
        // Call Acceptor::NewConnection if it is acceptor channel
        // Call ConnectionHandler::OnMessage if it is client channel
        if(callbacks_.read_callback)
            callbacks_.read_callback();
    }

    // Handle write events BEFORE close events.
    // When RDHUP arrives with EPOLLOUT (client half-closed but socket is writable),
    // the server may have a buffered response (queued via CloseAfterWrite) that must
    // flush before the fd is closed.
    if(events & EVENT_WRITE){
        if(callbacks_.write_callback)
            callbacks_.write_callback();
    }

    // Handle close events AFTER read AND write.
    // Only close if no other handler already dealt with it:
    //   - READ set: OnMessage handled EOF, armed close_after_write for deferred close
    //   - WRITE set: CallWriteCb flushed response, may have closed via close_after_write
    // For RDHUP/HUP-only (no READ, no WRITE), close immediately.
    if(events & (EVENT_RDHUP | EVENT_HUP)){
        bool handled_by_io = (events & EVENT_READ) || (events & EVENT_WRITE);
        if (!handled_by_io && !is_channel_closed()) {
            if(callbacks_.close_callback)
                callbacks_.close_callback();
            CloseChannel();
        }
        return;
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
