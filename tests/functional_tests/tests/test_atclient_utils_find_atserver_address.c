#include <atclient/atclient_utils.h>
#include <atlogger/atlogger.h>
#include <functional_tests/config.h>
#include <stdlib.h>
#include <string.h>

#define TAG "test_atclient_find_atserver_address"

#define UNDEFINED_ATSIGN_WITHOUT_AT ",,,,"

static int test_1_find_atserver_address_should_pass();
static int test_2_find_atserver_address_should_fail();

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  if ((ret = test_1_find_atserver_address_should_pass()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_find_atserver_address_should_pass: %d\n", ret);
    goto exit;
  }

  if ((ret = test_2_find_atserver_address_should_fail()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_2_find_atserver_address_should_fail: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;

exit: { return ret; }
}

static int test_1_find_atserver_address_should_pass() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_find_atserver_address_should_pass Begin\n");

  const char *atsign = FIRST_ATSIGN;
  const char *expected_host = FIRST_ATSIGN_ATSERVER_HOST;
  int expected_port = FIRST_ATSIGN_ATSERVER_PORT;

  char *atserver_host = NULL;
  int atserver_port = 0;

  if ((ret = atclient_utils_find_atserver_address(ATDIRECTORY_HOST, ATDIRECTORY_PORT, atsign, &atserver_host,
                                                  &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_find_atserver_address: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atserver_host: %s\n", atserver_host);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atserver_port: %d\n", atserver_port);

  if (strcmp(atserver_host, expected_host) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver_host is %s (expected: %s)\n", atserver_host,
                 expected_host);
    ret = 1;
    goto exit;
  }

  if (atserver_port != expected_port) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver_port doesn't match\n");
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(atserver_host);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_find_atserver_address_should_pass End: %d\n", ret);
  return ret;
}
}

static int test_2_find_atserver_address_should_fail() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_find_atserver_address_should_fail Begin\n");

  char *atserver_host = NULL;
  int atserver_port = 0;

  if ((ret = atclient_utils_find_atserver_address(ATDIRECTORY_HOST, ATDIRECTORY_PORT, UNDEFINED_ATSIGN_WITHOUT_AT,
                                                  &atserver_host, &atserver_port)) == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_find_atserver_address passed with exit code 0, when it was expected to fail... %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(atserver_host);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_find_atserver_address_should_fail End: %d\n", ret);
  return ret;
}
}
