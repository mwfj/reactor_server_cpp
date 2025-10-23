#include "common.h"

class Buffer{
private:
    std::string buf_;
public:
    Buffer() = default;
    ~Buffer() = default;

    // Append string without contain metadata
    void Append(const char*, size_t);
    // Append string containing metadata
    void AppendWithHead(const char* , size_t);

    void Erase(size_t, size_t);
    void Clear();

    size_t Size() const;
    const char* Data() const;
};