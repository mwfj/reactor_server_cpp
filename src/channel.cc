#include "channel.h"

// Channel::Channel(std::shared_ptr<EpollHandler> _ep, int _fd) : fd_(_fd), ep_(_ep){}
Channel::Channel(std::shared_ptr<Dispatcher> _dispatcher, int _fd) 
    : fd_(_fd), event_dispatcher_(_dispatcher){}

Channel::~Channel() {
    CloseChannel();
}

void Channel::HandleEvent() {
    if(is_channel_closed_) {
        return;
    }

    const uint32_t events = devent_;

    if(events & EPOLLERR){
        CloseChannel();
        return;
    }

    if(events & (EPOLLIN | EPOLLPRI)){
        if(read_fn_) {
            read_fn_();
        }
        if(is_channel_closed_) {
            return;
        }
    }

    if(events & (EPOLLRDHUP | EPOLLHUP)){
        CloseChannel();
        return;
    }
}

void Channel::NewConnection(SocketHandler& handler){
    InetAddr clientAddr;

    while(true){
        int client_fd = handler.Accept(clientAddr);

        if(client_fd < 0){
            break;
        }

        auto ep_shared = event_dispatcher_.lock();
        if(!ep_shared){
            ::close(client_fd);
            continue;
        }

        std::shared_ptr<Channel> clientCh(new Channel(ep_shared, client_fd));

        // Set callback using shared_ptr to keep channel alive during callback
        std::weak_ptr<Channel> weak_ch = clientCh;
        clientCh->SetReadCallBackFn([weak_ch]() {
            auto ch = weak_ch.lock();
            if(ch) {
                ch->OnMessage();
            }
        });
        // Enable ET mode for better performance
        clientCh->EnableETMode();
        // This calls UpdateEvent which registers with epoll
        clientCh->EnableReadMode(clientCh);
    }
}

void Channel::OnMessage(){
    if(is_channel_closed_) {
        return;
    }

    char buffer[MAX_BUFFER_SIZE];
    while(true){
        memset(buffer, 0, sizeof buffer);
        ssize_t nread = ::read(fd_, buffer, sizeof buffer);

        if(nread > 0){
            ssize_t total_written = 0;
            while(total_written < nread){
                ssize_t nwrite = ::send(fd_, buffer + total_written, static_cast<size_t>(nread - total_written), 0);
                if(nwrite > 0){
                    total_written += nwrite;
                    continue;
                }
                if(nwrite == -1 && errno == EINTR){
                    continue;
                }
                if(nwrite == -1 && ((errno == EAGAIN) || (errno == EWOULDBLOCK))){
                    return;
                }
                CloseChannel();
                return;
            }
        }else if(nread == 0){
            CloseChannel();
            return;
        }else{
            if(errno == EINTR){
                continue;
            }
            if((errno == EAGAIN) || (errno == EWOULDBLOCK)){
                break;
            }
            CloseChannel();
            return;
        }
    }
}

void Channel::SetReadCallBackFn(std::function<void()> fn){
    read_fn_ = fn;
}

void Channel::SetCloseCallBackFn(std::function<void()> fn){
    close_fn_ = fn;
}

void Channel::SetErrorCallBackFn(std::function<void()> fn){
    error_fn_ = fn;
}

void Channel::CloseChannel(){
    if(is_channel_closed_){
        return;
    }
    is_channel_closed_ = true;

    // Call the close callback before actually closing
    if(close_fn_){
        close_fn_();
    }

    if(fd_ != -1){
        ::close(fd_);
        fd_ = -1;
    }

    is_epoll_in_ = false;
    event_ = 0;
    devent_ = 0;
}
