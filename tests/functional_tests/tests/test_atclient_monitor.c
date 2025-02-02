#include "functional_tests/config.h"
#include "functional_tests/helpers.h"
#include <atchops/aes.h>
#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atclient/atclient.h>
#include <atclient/atclient_utils.h>
#include <atclient/encryption_key_helpers.h>
#include <atclient/monitor.h>
#include <atclient/notify.h>
#include <atclient/string_utils.h>
#include <atlogger/atlogger.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "test_atclient_monitor"

#define ATKEY_KEY "test_atclient_monitor"
#define ATKEY_NAMESPACE "functional_tests"
#define ATKEY_SHAREDBY FIRST_ATSIGN
#define ATKEY_SHAREDWITH SECOND_ATSIGN
#define ATKEY_VALUE "Test Value 12345 Meow"

#define MONITOR_REGEX ".*"

static int monitor_pkam_auth(atclient *monitor_conn, const atclient_atkeys *atkeys, const char *atsign);
static int send_notification(atclient *atclient);
static int monitor_for_notification(atclient *monitor_conn, atclient *atclient2);

static int test_1_start_monitor(atclient *monitor_conn);
static int test_2_send_notification(atclient *atclient);
static int test_3_monitor_for_notification(atclient *monitor_conn, atclient *atclient2);
static int test_4_re_pkam_auth_and_start_monitor(atclient *monitor_conn);
static int test_5_send_notification(atclient *atclient);
static int test_6_monitor_for_notification(atclient *monitor_conn, atclient *atclient2);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient1;
  atclient_init(&atclient1);

  atclient_atkeys atkeys_sharedby;
  atclient_atkeys_init(&atkeys_sharedby);

  atclient monitor_conn;
  atclient_monitor_init(&monitor_conn);

  atclient atclient2;
  atclient_init(&atclient2);

  atclient_atkeys atkeys_sharedwith;
  atclient_atkeys_init(&atkeys_sharedwith);

  if ((ret = functional_tests_set_up_atkeys(&atkeys_sharedby, ATKEY_SHAREDBY)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set up atkeys_sharedby: %d\n", ret);
    goto exit;
  }

  if ((ret = functional_tests_pkam_auth(&atclient1, &atkeys_sharedby, ATKEY_SHAREDBY)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  if ((ret = functional_tests_set_up_atkeys(&atkeys_sharedwith, ATKEY_SHAREDWITH)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set up atkeys_sharedby: %d\n", ret);
    goto exit;
  }

  if ((ret = monitor_pkam_auth(&monitor_conn, &atkeys_sharedwith, ATKEY_SHAREDWITH)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  atclient_monitor_set_read_timeout(&monitor_conn, 5*1000);

  if ((ret = functional_tests_pkam_auth(&atclient2, &atkeys_sharedwith, ATKEY_SHAREDWITH)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  if ((ret = test_1_start_monitor(&monitor_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_start_monitor: %d\n", ret);
    goto exit;
  }

  if ((ret = test_2_send_notification(&atclient1)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_3_send_notification: %d\n", ret);
    goto exit;
  }

  if ((ret = test_3_monitor_for_notification(&monitor_conn, &atclient2)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_4_read_notification: %d\n", ret);
    goto exit;
  }

  if ((ret = test_4_re_pkam_auth_and_start_monitor(&monitor_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_4_re_pkam_auth_and_start_monitor: %d\n", ret);
    goto exit;
  }

  if ((ret = test_5_send_notification(&atclient1)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_5_send_notification: %d\n", ret);
    goto exit;
  }

  if ((ret = test_6_monitor_for_notification(&monitor_conn, &atclient2)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_6_monitor_for_notification: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  if ((functional_tests_tear_down_sharedenckeys(&atclient1, ATKEY_SHAREDWITH)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to tear down sharedenckeys: %d\n", ret);
  }
  atclient_atkeys_free(&atkeys_sharedby);
  atclient_atkeys_free(&atkeys_sharedwith);
  atclient_free(&atclient1);
  atclient_free(&atclient2);
  atclient_free(&monitor_conn);
  return ret;
}
}

static int monitor_pkam_auth(atclient *monitor_conn, const atclient_atkeys *atkeys, const char *atsign) {
  int ret = 1;

  atclient_authenticate_options authenticate_options;
  atclient_authenticate_options_init(&authenticate_options);

  if((ret = atclient_authenticate_options_set_atdirectory_host(&authenticate_options, ATDIRECTORY_HOST)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_authenticate_options_set_atdirectory_host: %d\n", ret);
    goto exit;
  }

  if((ret = atclient_authenticate_options_set_atdirectory_port(&authenticate_options, ATDIRECTORY_PORT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_authenticate_options_set_atdirectory_port: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_monitor_pkam_authenticate(monitor_conn, atsign, atkeys, &authenticate_options)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_monitor_pkam_authenticate: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_authenticate_options_free(&authenticate_options);
  return ret;
}
}

static int send_notification(atclient *atclient) {
  int ret = 1;

  atclient_notify_params params;
  atclient_notify_params_init(&params);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_shared_key(&atkey, ATKEY_KEY, ATKEY_SHAREDBY, ATKEY_SHAREDWITH, ATKEY_NAMESPACE)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create atkey: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_notify_params_set_operation(&params, ATCLIENT_NOTIFY_OPERATION_UPDATE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set operation: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_notify_params_set_atkey(&params, &atkey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set atkey: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_notify_params_set_value(&params, ATKEY_VALUE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set value: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_notify_params_set_should_encrypt(&params, true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set should_encrypt: %d\n", ret);
    goto exit;
  }

  params.notification_expiry = 1000;

  if ((ret = atclient_notify(atclient, &params, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to notify: %d\n", ret);
    goto exit;
  }
exit: {
  atclient_atkey_free(&atkey);
  atclient_notify_params_free(&params);
  return ret;
}
}

static int monitor_for_notification(atclient *monitor_conn, atclient *atclient2) {
  int ret = 1;

  atclient_monitor_response message;
  atclient_monitor_response_init(&message);

  const int max_tries = 10;
  int tries = 1;

  while (tries <= max_tries) {
    if ((ret = atclient_monitor_read(monitor_conn, atclient2, &message, NULL)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read monitor message: %d\n", ret);
      tries++;
      continue;
    }

    if (!atclient_atnotification_is_decrypted_value_initialized(&(message.notification))) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Decrypted value is not initialized\n");
      tries++;
      continue;
    }

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Decrypted Value: %s\n", message.notification.decrypted_value);

    // compare the decrypted value with the expected value
    if (strcmp(message.notification.decrypted_value, ATKEY_VALUE) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Decrypted value does not match expected value\n");
      tries++;
      continue;
    }

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Tries: %d\n", tries);

    usleep(1000);

    ret = 0;
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read monitor message after %d tries\n", max_tries);

  ret = 1;
  goto exit;
exit: {
  atclient_monitor_response_free(&message);
  return ret;
}
}

static int test_1_start_monitor(atclient *monitor_conn) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_start_monitor Start\n");

  ret = atclient_monitor_start(monitor_conn, MONITOR_REGEX);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Started monitor\n");

  goto exit;

exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_start_monitor End: %d\n", ret);
  return ret;
}
}

static int test_2_send_notification(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_send_notification Start\n");

  if ((ret = send_notification(atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send notification: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_send_notification End: %d\n", ret);
  return ret;
}
}

static int test_3_monitor_for_notification(atclient *monitor_conn, atclient *atclient2) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_monitor_for_notification Start\n");

  if ((ret = monitor_for_notification(monitor_conn, atclient2)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to monitor for notification: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_monitor_for_notification End: %d\n", ret);
  return ret;
}
}

static int test_4_re_pkam_auth_and_start_monitor(atclient *monitor_conn) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_re_pkam_auth_and_start_monitor Start\n");

  atclient_authenticate_options authenticate_options;
  atclient_authenticate_options_init(&authenticate_options);

  char *atserver_host = strdup(monitor_conn->atserver_connection.host);
  int atserver_port = monitor_conn->atserver_connection.port;

  if((ret = atclient_authenticate_options_set_atserver_host(&authenticate_options, atserver_host)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_authenticate_options_set_atserver_host: %d\n", ret);
    goto exit;
  }

  if((ret = atclient_authenticate_options_set_atserver_port(&authenticate_options, atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_authenticate_options_set_atserver_port: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_monitor_pkam_authenticate(monitor_conn, monitor_conn->atsign, &(monitor_conn->atkeys), &authenticate_options)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_monitor_start(monitor_conn, MONITOR_REGEX)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Started monitor\n");

  ret = 0;
  goto exit;
exit: {
  free(atserver_host);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_re_pkam_auth_and_start_monitor End: %d\n", ret);
  return ret;
}
}

static int test_5_send_notification(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_5_send_notification Start\n");

  if ((ret = send_notification(atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send notification: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_5_send_notification End: %d\n", ret);
  return ret;
}
}

static int test_6_monitor_for_notification(atclient *monitor_conn, atclient *atclient2) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_6_monitor_for_notification Start\n");

  if ((ret = monitor_for_notification(monitor_conn, atclient2)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to monitor for notification: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_6_monitor_for_notification End: %d\n", ret);
  return ret;
}
}
