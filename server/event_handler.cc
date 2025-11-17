#include "event_handler.h"
#include "channel.h"

EventHandler::EventHandler(){
#if defined(__linux__)
    epoll_event_ = std::unique_ptr<EpollHandler>(new EpollHandler());
#elif defined(__APPLE__) || defined(__MACH__)
    kqueue_event_ = std::unique_ptr<KqueueHandler>(new KqueueHandler());
#endif
}

void EventHandler::UpdateEvent(std::shared_ptr<Channel> ch){
#if defined(__linux__)
    if(!epoll_event_){
        std::cout << "[Event Handler] Nullptr of epoll_event: " << strerror(errno) << std::endl;
        throw std::runtime_error("Nullptr of epoll_event");
    }
    epoll_event_ -> UpdateEvent(ch);
#elif defined(__APPLE__) || defined(__MACH__)
    if(!kqueue_event_){
        std::cout << "[Event Handler] Nullptr of kqueue_event: " << strerror(errno) << std::endl;
        throw std::runtime_error("Nullptr of kqueue_event");
    }
    kqueue_event_ -> UpdateEvent(ch);
#endif
}

void EventHandler::RemoveChannel(std::shared_ptr<Channel> ch) {
#if defined(__linux__)
    if(!epoll_event_){
        std::cout << "[Event Handler] Nullptr of epoll_event: " << strerror(errno) << std::endl;
        throw std::runtime_error("Nullptr of epoll_event");
    }
    epoll_event_ -> RemoveChannel(ch);
#elif defined(__APPLE__) || defined(__MACH__)
    if(!kqueue_event_){
        std::cout << "[Event Handler] Nullptr of kqueue_event: " << strerror(errno) << std::endl;
        throw std::runtime_error("Nullptr of kqueue_event");
    }
    kqueue_event_ -> RemoveChannel(ch);
#endif
}

std::vector<std::shared_ptr<Channel>> EventHandler::WaitForEvent(int timeout) {
#if defined(__linux__)
    if(!epoll_event_){
        std::cout << "[Event Handler] Nullptr of epoll_event: " << strerror(errno) << std::endl;
        throw std::runtime_error("Nullptr of epoll_event");
    }
    return epoll_event_ -> WaitForEvent(timeout);
#elif defined(__APPLE__) || defined(__MACH__)
    if(!kqueue_event_){
        std::cout << "[Event Handler] Nullptr of kqueue_event: " << strerror(errno) << std::endl;
        throw std::runtime_error("Nullptr of kqueue_event");
    }
    return kqueue_event_ -> WaitForEvent(timeout);
#endif
}