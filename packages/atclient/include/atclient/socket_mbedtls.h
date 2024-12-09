// IWYU pragma: private, include "atclient/net_socket.h"
// IWYU pragma: friend "net_socket_mbedtls.*"
#ifndef ATCLIENT_NET_SOCKET_MBEDTLS_H
#define ATCLIENT_NET_SOCKET_MBEDTLS_H
#include <atchops/platform.h>
#if defined(ATCLIENT_SOCKET_PROVIDER_MBEDTLS)
#include <atclient/socket_shared.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/threading.h>
#ifdef __cplusplus
extern "C" {
#endif

// Make this type more portable to consume later
struct atclient_raw_socket {
  mbedtls_net_context net;
};

struct atclient_tls_socket {
  struct atclient_raw_socket raw;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config ssl_config;
  mbedtls_x509_crt cacert;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
};
#ifdef __cplusplus
}
#endif
#endif
#endif
