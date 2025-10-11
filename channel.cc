#include "channel.h"

Channel::Channel(std::shared_ptr<EpollHandler> _ep, int _fd) : fd_(_fd), ep_(_ep){}



void Channel::HandleEvent() {
    // check whether a stream socket peer has either closed the connection
    // or shut down the writing half of the connection.
    if(devent_ & EPOLLRDHUP){
        close(fd_);
        // Don't throw - this is normal client disconnect
        return;
    }else if(devent_ & (EPOLLIN | EPOLLPRI)){
        // there has data in buffer
        if(read_fn_) {
            read_fn_();
        }
    }else if(devent_ & EPOLLOUT){
        //  reserve for future feature
    }else if(devent_ & EPOLLERR){
        close(fd_);
        return;
    }else if(devent_ & EPOLLHUP){
        close(fd_);
        return;
    }
}

void Channel::NewConnection(ConnectionHandler& handler){
    InetAddr clientAddr;
    int client_fd = handler.Accept(clientAddr);

    if(client_fd < 0){
        return;
    }

    // Get shared_ptr from weak_ptr
    auto ep_shared = ep_.lock();
    if(!ep_shared){
        close(client_fd);
        return;
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
    clientCh->EnableReadMode();  // This calls UpdateChannel which registers with epoll

    // Store the channel in EpollHandler for ownership management
    ep_shared->AddChannel(clientCh);
}

void Channel::OnMessage(){
    char buffer[MAX_BUFFER_SIZE];
    while(true){
        memset(buffer, 0, sizeof buffer);

        ssize_t nread = ::read(fd_, buffer, sizeof buffer);

        if(nread > 0){
            // receive the data and echo it back
            ::send(fd_, buffer, strlen(buffer), 0);

        }else if(nread == -1 && errno == EINTR){
            // interruptted by keyboard signal
            continue;

        }else if(nread == -1 && ((errno == EAGAIN) || (errno == EWOULDBLOCK))){
            // finished read
            break;
        }else if(nread == 0){
            // client disconnect
            close(fd_);
            break;
        }
    }
}

void Channel::SetReadCallBackFn(std::function<void()> fn){
    read_fn_ = fn;
}