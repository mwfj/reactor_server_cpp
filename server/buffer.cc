#include "buffer.h"

void Buffer::Append(const char *data, size_t size){
        buf_.append(data, size);
}

void Buffer::AppendWithHead(const char *data, size_t size){
    // Add header to store the length of the current string
    buf_.append(reinterpret_cast<const char*>(&size), 4);
    buf_.append(data, size);
}

void Buffer::Erase(size_t start, size_t len){
    buf_.erase(start, len);
}

void Buffer::Clear(){
    buf_.clear();
}

size_t Buffer::Size() const {
    return buf_.size();
}

const char* Buffer::Data() const {
    return buf_.data();
}