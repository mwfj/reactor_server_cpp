#pragma once
#include "common.h"

class Client{
private:
    int socketfd_ = -1;
    in_port_t port_;
    in_addr_t addr_;
    struct sockaddr_in servaddr_;
    char buf_[MAX_BUFFER_SIZE];
    bool quiet_mode_ = false;
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

    void Send(){
        if(send(socketfd_, buf_, strlen(buf_), 0) < 0){
            throw std::runtime_error("Send failed");
        }
    }

    void Receive(){
        memset(buf_, 0, MAX_BUFFER_SIZE);
        if(recv(socketfd_, buf_, sizeof(buf_) - 1, 0) < 0){
            throw std::runtime_error("Receive failed");
        }
        if(!quiet_mode_){
            std::cout << "[Client] Received: " << buf_ << std::endl;
        }
    }

    void SetQuietMode(bool quiet){
        quiet_mode_ = quiet;
    }

    void Close(){
        if(socketfd_ != -1){
            close(socketfd_);
            socketfd_ = -1;
        }
    }
};