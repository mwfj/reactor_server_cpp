#include "epoll_handler.h"

EpollHandler::EpollHandler(){
    if((epollfd_ = ::epoll_create(1)) == -1){
        throw std::runtime_error("Epoll created failed");
    }
}

EpollHandler::~EpollHandler(){
    close(epollfd_);
}