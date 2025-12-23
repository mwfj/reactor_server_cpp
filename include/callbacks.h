#pragma once

#include "common.h"

/**
 * Record all of the callback function that defined in this project
 */
class ConnectionHandler;
class Dispatcher;

namespace CALLBACKS_NAMESPACE {
    // Connection handler
    using ConnOnMsgCallback    = std::function<void(std::shared_ptr<ConnectionHandler>, std::string&)>;
    using ConnCompleteCallback = std::function<void(std::shared_ptr<ConnectionHandler>)>;
    using ConnCloseCallback    = std::function<void(std::shared_ptr<ConnectionHandler>)>;
    using ConnErrorCallback    = std::function<void(std::shared_ptr<ConnectionHandler>)>;

    struct ConnCallbacks {
        ConnOnMsgCallback    on_message_callback = nullptr;
        ConnCompleteCallback complete_callback   = nullptr;
        ConnCloseCallback    close_callback      = nullptr;
        ConnErrorCallback    error_callback      = nullptr;
    };

    // Channel
    using ChannelReadCallback  = std::function<void()>;
    using ChannelWriteCallback = std::function<void()>;
    using ChannelCloseCallback = std::function<void()>;
    using ChannelErrorCallback = std::function<void()>;

    struct ChannelCallbacks {
        // Read callback
        // - Callback Acceptor::NewConnection if is the acceptor channel
        // - Callback Channel::OnMessage if is the client channel
        ChannelReadCallback  read_callback  = nullptr;
        ChannelWriteCallback write_callback = nullptr;
        ChannelCloseCallback close_callback = nullptr;
        ChannelErrorCallback error_callback = nullptr;
    };

    // NetServer
    using NetSrvConnCallback         = std::function<void(std::shared_ptr<ConnectionHandler>)>;
    using NetSrvCloseConnCallback    = std::function<void(std::shared_ptr<ConnectionHandler>)>;
    using NetSrvErrorCallback        = std::function<void(std::shared_ptr<ConnectionHandler>)>;
    using NetSrvOnMsgCallback        = std::function<void(std::shared_ptr<ConnectionHandler>, std::string&)>;
    using NetSrvSendCompleteCallback = std::function<void(std::shared_ptr<ConnectionHandler>)>;
    using NetSrvTimerCallback        = std::function<void(std::shared_ptr<Dispatcher>)>;

    struct NetSrvCallbacks {
        NetSrvConnCallback         new_conn_callback      = nullptr;
        NetSrvCloseConnCallback    close_conn_callback    = nullptr;
        NetSrvErrorCallback        error_callback         = nullptr;
        NetSrvOnMsgCallback        on_message_callback    = nullptr;
        NetSrvSendCompleteCallback send_complete_callback = nullptr;
        NetSrvTimerCallback        timer_callback         = nullptr;
    };

    // Dispatcher
    using DispatcherTOTriggerCallback = std::function<void(std::shared_ptr<Dispatcher>)>;
    using DispatcherTimerCallback      = std::function<void(int)>;

    struct DispatcherCallbacks {    
        DispatcherTOTriggerCallback  timeout_trigger_callback = nullptr;
        DispatcherTimerCallback      timer_callback           = nullptr;
    };


} // namespace CALLBACKS_NAMESPACE