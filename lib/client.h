#pragma once
#include "common.h"

/**
 * Client class that handles length-prefix protocol communication
 * Protocol: [4-byte length header][message data]
 */
class Client{
private:
    int socketfd_ = -1;
    in_port_t port_;
    in_addr_t addr_;
    struct sockaddr_in servaddr_;
    char buf_[MAX_BUFFER_SIZE];
    std::string received_message_;
    bool quiet_mode_ = false;

    /**
     * Helper: Receive exactly n bytes from socket (handles partial reads)
     */
    bool RecvN(void* buffer, size_t n) {
        size_t total_received = 0;
        char* ptr = static_cast<char*>(buffer);

        while(total_received < n) {
            ssize_t received = recv(socketfd_, ptr + total_received, n - total_received, 0);
            if(received <= 0) {
                if(received == 0) {
                    // Connection closed
                    return false;
                }
                if(errno == EINTR) {
                    continue;  // Interrupted, try again
                }
                throw std::runtime_error("Receive failed");
            }
            total_received += received;
        }
        return true;
    }

    /**
     * Helper: Send exactly n bytes to socket (handles partial writes)
     */
    bool SendN(const void* buffer, size_t n) {
        size_t total_sent = 0;
        const char* ptr = static_cast<const char*>(buffer);

        while(total_sent < n) {
            ssize_t sent = send(socketfd_, ptr + total_sent, n - total_sent, 0);
            if(sent <= 0) {
                if(errno == EINTR) {
                    continue;  // Interrupted, try again
                }
                throw std::runtime_error("Send failed");
            }
            total_sent += sent;
        }
        return true;
    }

public:
    Client() = default;
    Client(int _port, const char* _addr, const char *_buf):
        port_(static_cast<in_port_t>(_port))
    {
        addr_ = inet_addr(_addr);
        strncpy(buf_, _buf, sizeof(buf_) - 1);
        buf_[sizeof(buf_) - 1] = '\0';
    }
    ~Client(){
        Close();
    }

    void Init(){
        socketfd_ = socket(AF_INET, SOCK_STREAM, 0);
        if(socketfd_ == -1)
            throw std::runtime_error("Socket creation failed");

        memset(&servaddr_, 0, sizeof servaddr_);
        servaddr_.sin_family = AF_INET;
        servaddr_.sin_addr.s_addr = addr_;
        servaddr_.sin_port = htons(port_);
    }

    void Connect(){
        if(connect(socketfd_, (struct sockaddr *)&servaddr_, sizeof servaddr_) < 0){
            if(!quiet_mode_){
                std::cout << "[Client] Connection error, port: " << port_ << std::endl;
            }
            Close();
            throw std::runtime_error("Connection Error");
        }else{
            if(!quiet_mode_){
                std::cout << "[Client] Connection success, port: " << port_ << std::endl;
            }
        }
    }

    /**
     * Send message without length header (raw send)
     * Sends the message data directly to the server
     */
    void Send(){
        size_t len = strlen(buf_);
        if(!SendN(buf_, len)){
            throw std::runtime_error("Send failed");
        }
    }

    /**
     * Receive message with length-prefix protocol
     * Reads 4-byte header first, then reads exact message length
     * This matches the server's Buffer::AppendWithHead format
     */
    void Receive(){
        // First, read the 4-byte length header
        uint32_t msg_length = 0;
        if(!RecvN(&msg_length, 4)){
            throw std::runtime_error("Receive header failed");
        }

        // Validate message length
        if(msg_length == 0) {
            received_message_ = "";
            memset(buf_, 0, MAX_BUFFER_SIZE);
            if(!quiet_mode_){
                std::cout << "[Client] Received empty message" << std::endl;
            }
            return;
        }

        if(msg_length > MAX_BUFFER_SIZE - 1) {
            throw std::runtime_error("Message too large");
        }

        // Read the actual message data
        memset(buf_, 0, MAX_BUFFER_SIZE);
        if(!RecvN(buf_, msg_length)){
            throw std::runtime_error("Receive message failed");
        }

        buf_[msg_length] = '\0';  // Null terminate
        received_message_ = std::string(buf_, msg_length);

        if(!quiet_mode_){
            std::cout << "[Client] Received: " << received_message_ << std::endl;
        }
    }

    void SetQuietMode(bool quiet){
        quiet_mode_ = quiet;
    }

    const std::string& GetReceivedMessage() const {
        return received_message_;
    }

    void Close(){
        if(socketfd_ != -1){
            close(socketfd_);
            socketfd_ = -1;
        }
    }
};
