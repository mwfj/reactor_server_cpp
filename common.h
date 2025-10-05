#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<cstring>
#include<stdexcept>
#include<iostream>
#include<signal.h>
#include<sys/wait.h>
#include<sys/epoll.h>
#include<fcntl.h>
#include<netinet/tcp.h>
#include<errno.h>
#include <chrono>
#include <thread>

#define MAX_BUFFER_SIZE 1024
#define MAX_REPLY_SIZE 50
#define NUMBER_OF_CHILD_PROCESSES 25
#define MAX_CONNECTIONS 10000  // Maximum concurrent connections (epoll scales beyond FD_SETSIZE)
#define MAX_EPOLL_EVENTS 1000  // Max events to process per epoll_wait call