#include "channel.h"

Channel::Channel(std::shared_ptr<Dispatcher> _dispatcher, int _fd) 
    : fd_(_fd), event_dispatcher_(_dispatcher){}

Channel::~Channel() {
    // Safety net: close the fd if it's still valid regardless of
    // is_channel_closed_ state. This covers the edge case where
    // CloseChannel() enqueued the teardown to the dispatcher (off-loop
    // path) but the task was discarded because the dispatcher stopped.
    if(fd_ != -1){
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
    // Clear both EVENT_READ and EVENT_RDHUP (set together by EnableReadMode).
    // On kqueue, UpdateEvent() treats events != 0 as "still registered".
    // Without clearing RDHUP, the channel stays in channel_map_ with
    // is_read_event_ true even after both filters are deleted.
    event_ &= ~(EVENT_READ | EVENT_RDHUP);
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
    // Invoke the close callback (ConnectionHandler::CallCloseCb), which either:
    //   1. Closes inline (calls CloseChannel internally), OR
    //   2. Defers if close_after_write_ with buffered data (response still flushing)
    // Do NOT call CloseChannel here — CallCloseCb handles it when appropriate.
    if(events & (EVENT_RDHUP | EVENT_HUP)){
        // Only close if:
        // - Channel isn't already closed (by read/write callbacks), AND
        // - No close callback is wired (fallback), OR
        // - The close callback doesn't defer (CallCloseCb returns early if
        //   close_after_write_ is set with buffered data)
        if (!is_channel_closed()) {
            if(callbacks_.close_callback) {
                callbacks_.close_callback();
            } else {
                CloseChannel();
            }
        }
        // Note: if CallCloseCb deferred (close_after_write_ + buffer), the channel
        // stays open. CallWriteCb will close after the buffer drains. For async
        // handlers, DoSend will enable write mode when data arrives.
        return;
    }

    // Handle error events
    if(events & EVENT_ERR){
        if(callbacks_.error_callback)
            callbacks_.error_callback();
    }
}

void Channel::InvokeCloseCallback() {
    if (callbacks_.close_callback) {
        callbacks_.close_callback();
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

    std::shared_ptr<Dispatcher> ep_shared = event_dispatcher_.lock();

    // Off-loop path: enqueue the entire teardown so RemoveChannel sees
    // valid fd_ and is_read_event_ state. Without this, the old code
    // would enqueue RemoveChannel then immediately clear fd_ = -1 and
    // is_read_event_ = false, causing the enqueued task to skip kqueue/
    // epoll deletion and channel_map_ cleanup.
    // The CAS above prevents HandleEvent from firing callbacks while
    // the teardown is pending. The shared_ptr in the lambda keeps the
    // Channel alive until cleanup completes.
    if (ep_shared && !ep_shared->is_on_loop_thread()
        && !ep_shared->was_stopped()) {
        auto self = shared_from_this();
        ep_shared->EnQueue([self]() {
            auto disp = self->event_dispatcher_.lock();
            if (self->fd_ != -1 && self->is_read_event_ && disp) {
                disp->RemoveChannel(self);
            }
            if (self->fd_ != -1) {
                ::close(self->fd_);
                self->fd_ = -1;
            }
            self->is_read_event_ = false;
            self->event_ = 0;
            self->devent_ = 0;
        });
        return;
    }

    // On-loop or dispatcher unavailable: execute inline
    // IMPORTANT: Remove fd from epoll BEFORE closing it
    // This prevents epoll fd reuse bugs when the OS reuses the fd number
    if(fd_ != -1 && is_read_event_ && ep_shared){
        ep_shared->RemoveChannel(shared_from_this());
    }

    if(fd_ != -1){
        ::close(fd_);
        fd_ = -1;
    }

    is_read_event_ = false;
    event_ = 0;
    devent_ = 0;
}
