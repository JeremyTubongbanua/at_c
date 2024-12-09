#include <atchops/platform.h>
#include <atclient/socket.h>
// Most of the implementation for net_socket is platform specific,
// See the other net_socket_*.c files

struct atclient_socket_read_options atclient_socket_read_until_char(char until) {
  return (struct atclient_socket_read_options){
      ATCLIENT_SOCKET_READ_UNTIL_CHAR,
      {.until_char = until},
  };
}

// struct atclient_socket_read_options atclient_socket_read_num_bytes(size_t bytes) {
//   return (struct atclient_socket_read_options){
//       ATCLIENT_SOCKET_READ_NUM_BYTES,
//       {.num_bytes = bytes},
//   };
// }
