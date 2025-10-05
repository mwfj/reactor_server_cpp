#include "server.h"

class ReactorServer {
private:
    bool is_running_ = false;
public:
    ReactorServer();
    ~ReactorServer();
    void Start();
    void Stop(){is_running_ = false;}
    void Run();
    bool is_running() const {return is_running_;}
};