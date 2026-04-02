#pragma once
#include "common.h"
#include "socket_handler.h"
#include "inet_addr.h"
#include "channel.h"
#include "dispatcher.h"

class Acceptor{
private:
    std::shared_ptr<Dispatcher> event_dispatcher_;
    std::unique_ptr<SocketHandler> servsock_;  // Sole owner of listening socket
    std::shared_ptr<Channel> acceptor_channel_;

    // Reserved fd for the "idle fd trick" — when accept() fails with EMFILE
    // (per-process fd limit), close this fd to make room for one accept,
    // immediately close the accepted fd, then re-open the reserved fd.
    // This drains the pending connection from the listen queue, preventing
    // ET mode starvation where the server permanently stops accepting.
    int idle_fd_ = -1;

    std::function<void(std::unique_ptr<SocketHandler>)> new_conn_cb_;
    // Set by MarkClosing() from a non-dispatcher thread (StopAccepting)
    // before enqueuing CloseListenSocket. Checked by deferred retries to
    // prevent accepting new connections after shutdown starts.
    std::atomic<bool> closing_{false};
public:
    Acceptor() = delete;
    Acceptor(std::shared_ptr<Dispatcher>, const std::string&, const size_t);
    ~Acceptor();

    void NewConnection(); // process the request from client

    // Signal that the listen socket is about to be closed. Thread-safe.
    // Called from StopAccepting before enqueuing CloseListenSocket so
    // deferred retries in the task queue see the flag immediately.
    void MarkClosing() { closing_.store(true, std::memory_order_release); }

    // Close the listening socket and remove from epoll, releasing the port
    // immediately. Safe to call from the conn_dispatcher thread (sequentially
    // with accept callbacks). After this, ~Acceptor is a no-op.
    void CloseListenSocket();

    void SetNewConnCb(std::function<void(std::unique_ptr<SocketHandler>)>);
};