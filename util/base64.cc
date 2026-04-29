#include "base64.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

namespace base64_util {

std::string EncodeNoNewline(const void* data, size_t size) {
    if (size == 0 || data == nullptr) return std::string();
    BIO* b64 = BIO_new(BIO_f_base64());
    if (!b64) return std::string();
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem) {
        BIO_free(b64);
        return std::string();
    }
    BIO* chain = BIO_push(b64, mem);
    int wrote = BIO_write(chain, data, static_cast<int>(size));
    if (wrote < 0 || static_cast<size_t>(wrote) != size) {
        BIO_free_all(chain);
        return std::string();
    }
    if (BIO_flush(chain) <= 0) {
        BIO_free_all(chain);
        return std::string();
    }
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(chain, &bptr);
    std::string out;
    if (bptr && bptr->length > 0) {
        out.assign(bptr->data, bptr->length);
    }
    BIO_free_all(chain);
    return out;
}

}  // namespace base64_util
