#include "functional_tests/helpers.h"
#include "functional_tests/config.h"
#include <atclient/atclient.h>
#include <atclient/atclient_utils.h>
#include <atclient/constants.h>
#include <atclient/string_utils.h>
#include <atlogger/atlogger.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "functional_tests_helpers"

int functional_tests_set_up_atkeys(atclient_atkeys *atkeys, const char *atsign) {
  int ret = 1;

  char *path = NULL;

  if ((ret = functional_tests_get_atkeys_path(atsign, &path)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get atkeys path for atSign \"%s\"\n", atsign);
    goto exit;
  }

  if ((ret = atclient_atkeys_populate_from_path(atkeys, path)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys_sharedwith from path: %d\n", ret);
    goto exit;
  }

  goto exit;

exit: {
  if (path != NULL) {
    free(path);
  }
  return ret;
}
}

int functional_tests_pkam_auth(atclient *atclient, atclient_atkeys *atkeys, const char *atsign) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "functional_tests_pkam_auth Begin\n");

  if (atclient == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    return ret;
  }

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (atsign == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign is NULL\n");
    return ret;
  }

  atclient_authenticate_options authenticate_options;
  atclient_authenticate_options_init(&authenticate_options);

  if ((ret = atclient_authenticate_options_set_atdirectory_host(&authenticate_options, ATDIRECTORY_HOST)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_authenticate_options_set_atdirectory_host: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_authenticate_options_set_atdirectory_port(&authenticate_options, ATDIRECTORY_PORT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_authenticate_options_set_atdirectory_port: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(atclient, atsign, atkeys, &authenticate_options, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
    goto exit;
  }

  atclient_set_read_timeout(atclient, 5 * 1000); // 5 second read timeout

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "pkam authenticated\n");

  goto exit;

exit: {
  atclient_authenticate_options_free(&authenticate_options);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "functional_tests_pkam_auth End (%d)\n", ret);
  return ret;
}
}

int functional_tests_publickey_exists(atclient *atclient, const char *key, const char *shared_by,
                                      const char *knamespace) {
  int ret = -1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const short atkeystrsize = 128;
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  const short commandsize = 256;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  size_t commandlen = 0;

  const size_t recvsize = 256;
  char recv[recvsize];
  memset(recv, 0, sizeof(char) * recvsize);
  size_t recvlen = 0;

  if (knamespace == NULL) {
    snprintf(atkeystr, atkeystrsize, "%s%s", key, shared_by);
  } else {
    snprintf(atkeystr, atkeystrsize, "%s.%s%s", key, knamespace, shared_by);
  }

  snprintf(command, commandsize, "plookup:%s\r\n", atkeystr);
  commandlen = strlen(command);

  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)command, commandlen,
                                      (unsigned char *)recv, recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_string_utils_starts_with(recv, "data:")) {
    ret = false;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "publickey does not exist: \"%s\"\n", recv);
    goto exit;
  }

  if (recvlen <= 0) {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "error occured with recvlen <= 0: %lu. Recv: \"%s\"\n", recvlen,
                 recv);
    goto exit;
  }

  ret = true;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

int functional_tests_selfkey_exists(atclient *atclient, const char *key, const char *shared_by,
                                    const char *knamespace) {
  int ret = -1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const short atkeystrsize = 128;
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  const short commandsize = 256;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  size_t commandlen = 0;

  const size_t recvsize = 256;
  char recv[recvsize];
  memset(recv, 0, sizeof(char) * recvsize);
  size_t recvlen = 0;

  if (knamespace == NULL) {
    snprintf(atkeystr, atkeystrsize, "%s%s", key, shared_by);
  } else {
    snprintf(atkeystr, atkeystrsize, "%s.%s%s", key, knamespace, shared_by);
  }

  snprintf(command, commandsize, "llookup:%s\r\n", atkeystr);
  commandlen = strlen(command);

  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)command, commandlen,
                                      (unsigned char *)recv, recvsize, &recvlen)) != 0) {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_string_utils_starts_with(recv, "data:")) {
    ret = false;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "selfkey does not exist: \"%s\"\n", recv);
    goto exit;
  }

  if (recvlen <= 0) {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "selfkey does not exist (%lu): \"%s\"\n", recvlen, recv);
    goto exit;
  }

  ret = true;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

int functional_tests_sharedkey_exists(atclient *atclient, const char *key, const char *shared_by,
                                      const char *shared_with, const char *knamespace) {
  int ret = -1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const short atkeystrsize = 128;
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  const short commandsize = 256;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  size_t commandlen = 0;

  const size_t recvsize = 256;
  char recv[recvsize];
  memset(recv, 0, sizeof(char) * recvsize);
  size_t recvlen = 0;

  if (knamespace == NULL) {
    snprintf(atkeystr, atkeystrsize, "%s:%s%s", shared_with, key, shared_by);
  } else {
    snprintf(atkeystr, atkeystrsize, "%s:%s.%s%s", shared_with, key, knamespace, shared_by);
  }

  snprintf(command, commandsize, "lookup:%s\r\n", atkeystr);
  commandlen = strlen(command);

  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)command, commandlen,
                                      (unsigned char *)recv, recvsize, &recvlen)) != 0) {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_string_utils_starts_with(recv, "data:")) {
    ret = false;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "sharedkey does not exist: \"%s\"\n", recv);
    goto exit;
  }

  if (recvlen <= 0) {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "sharedkey does not exist (%lu): \"%s\"\n", recvlen, recv);
    goto exit;
  }

  ret = true;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

int functional_tests_tear_down_sharedenckeys(atclient *atclient1, const char *recipient) {
  int ret = 1;

  if (atclient1 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    return ret;
  }

  if (recipient == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recipient is NULL\n");
    return ret;
  }

  if (!atclient_is_atsign_initialized(atclient1)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign is not initialized\n");
    return ret;
  }

  // TODO check if pkam authenticated

  atclient_atkey atkeyforme;
  atclient_atkey_init(&atkeyforme);

  atclient_atkey atkeyforthem;
  atclient_atkey_init(&atkeyforthem);

  char *client_atsign_with_at = NULL;
  char *recipient_atsign_with_at = NULL;

  char atkeystrtemp[ATCLIENT_ATKEY_FULL_LEN];

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "tear_down Begin\n");

  if ((ret = atclient_string_utils_atsign_with_at(atclient1->atsign, &client_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_string_utils_atsign_with_at(recipient, &recipient_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  char *client_atsign_without_at = client_atsign_with_at + 1;
  char *recipient_atsign_without_at = recipient_atsign_with_at + 1;

  memset(atkeystrtemp, 0, sizeof(char) * ATCLIENT_ATKEY_FULL_LEN);
  snprintf(atkeystrtemp, ATCLIENT_ATKEY_FULL_LEN, "shared_key.%s%s", recipient_atsign_without_at,
           client_atsign_with_at);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkeystrtemp: \"%s\"\n", atkeystrtemp);
  if ((ret = atclient_atkey_from_string(&atkeyforme, atkeystrtemp)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d\n", ret);
    goto exit;
  }

  memset(atkeystrtemp, 0, sizeof(char) * ATCLIENT_ATKEY_FULL_LEN);
  snprintf(atkeystrtemp, ATCLIENT_ATKEY_FULL_LEN, "%s:shared_key%s", recipient_atsign_with_at, client_atsign_with_at);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkeystrtemp: \"%s\"\n", atkeystrtemp);
  if ((ret = atclient_atkey_from_string(&atkeyforthem, atkeystrtemp)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_delete(atclient1, &atkeyforme, NULL, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "deleted shared enc key for me\n");

  if ((ret = atclient_delete(atclient1, &atkeyforthem, NULL, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "deleted shared enc key for them\n");

  ret = 0;
  goto exit;

exit: {
  atclient_atkey_free(&atkeyforme);
  atclient_atkey_free(&atkeyforthem);
  free(client_atsign_with_at);
  free(recipient_atsign_with_at);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "tear_down End (%d)\n", ret);
  return ret;
}
}

int functional_tests_get_atkeys_path(const char *atsign, char **path) {
  struct passwd *pw = getpwuid(getuid());
  const char *homedir = pw->pw_dir;
  const size_t path_size = strlen(homedir) + strlen("/.atsign/keys/") + strlen(atsign) + strlen("_key.atkeys") + 1;
  if ((*path = (char *)malloc(sizeof(char) * path_size)) == NULL) {
    return 1; // failed to allocate memory
  }
  memset(*path, 0, sizeof(char) * path_size);
  snprintf(*path, path_size, "%s/.atsign/keys/%s_key.atKeys", homedir, atsign);
  return 0;
}
