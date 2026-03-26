/* Minimal config for nghttp2 vendored build */
#ifndef NGHTTP2_CONFIG_H
#define NGHTTP2_CONFIG_H

#ifndef _WIN32
#  define HAVE_ARPA_INET_H 1
#  define HAVE_NETINET_IN_H 1
#endif

#endif /* NGHTTP2_CONFIG_H */
