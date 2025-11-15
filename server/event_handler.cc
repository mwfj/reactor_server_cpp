#include "event_handler.h"

EventHandler::EventHandler(){
#ifdef defined(__linux__)
    epoll_event_ = std::unique_ptr<EpollHandler>(new EpollHandler());
#elif defined(__APPLE__) || defined(__MACH__)
    kqueue_event_ = std::unique_ptr<KqueueHandler>(new KqueueHandler);
#endif
}

const int EventHandler::fd() const{
#ifdef defined(__linux__)
    return 
#elif defined(__APPLE__) || defined(__MACH__)
    return 
#endif
}