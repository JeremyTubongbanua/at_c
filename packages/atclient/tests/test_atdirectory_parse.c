#include "atdirectory.h"
#include "atlogger/atlogger.h"
#include <stdint.h>
#include <string.h>
#define BASE_TAG(X) "test_atdirectory_parse " X

static uint8_t test_1a_parse();
static uint8_t test_2a_bad_string();
static uint8_t test_2b_bad_port();

int main() {
  int ret = 0;
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  ret += test_1a_parse();
  ret += test_2a_bad_string();
  ret += test_2b_bad_port();

  if (ret > 0) {
    atlogger_log("test_atdirectory_parse", ATLOGGER_LOGGING_LEVEL_ERROR, "%d tests failed\n", ret);
  }
  return ret;
}

#define expect_uint(TEST_TAG, EXP, ACT)                                                                                \
  if (EXP != ACT) {                                                                                                    \
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%s: incorrect value (expected: %u, actual: %u)\n", TEST_TAG, EXP, \
                 ACT);                                                                                                 \
    return 1;                                                                                                          \
  }

#define expect_strn(TEST_TAG, EXP, ACT, LEN)                                                                           \
  if (ACT == NULL) {                                                                                                   \
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%s: expected to be %s, got NULL\n", TEST_TAG, EXP);               \
    return 1;                                                                                                          \
  }                                                                                                                    \
  if (strncmp(EXP, ACT, LEN) != 0) {                                                                                   \
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%s: incorrect string comparison, (expected: %s, actual: %.*s)\n", \
                 TEST_TAG, EXP, LEN, ACT);                                                                             \
    return 1;                                                                                                          \
  }

uint8_t test_1a_parse() {
  const char *TAG = BASE_TAG("1a");
  char *buffer = "foo.bar.baz:123";
  const uint16_t len = strlen(buffer);

  char *host;
  uint16_t port;

  int ret = atdirectory_parse_host_port_from_buf(buffer, len, &host, &port);

  expect_uint("exit code", 0, ret);
  expect_uint("port", 123, port);
  expect_strn("host", "foo.bar.baz", host, 11);

  free(host);
  return 0;
}

uint8_t test_2a_bad_string() {
  const char *TAG = BASE_TAG("2a");
  char *buffer = "foobarbaz";
  const uint16_t len = strlen(buffer);

  char *host;
  uint16_t port;

  int ret = atdirectory_parse_host_port_from_buf(buffer, len, &host, &port);

  if (ret == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "exit code: expected to be non-zero, got 0\n");
    return 1;
  }

  return 0;
}

uint8_t test_2b_bad_port() {
  const char *TAG = BASE_TAG("2b");
  char *buffer = "foobarbaz:asdf";
  const uint16_t len = strlen(buffer);

  char *host;
  uint16_t port;

  int ret = atdirectory_parse_host_port_from_buf(buffer, len, &host, &port);

  if (ret == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "exit code: expected to be non-zero, got 0\n");
    return 1;
  }
  if (host != NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "host: expected to be NULL, got %s\n", host);
    return 1;
  }

  return 0;
}
