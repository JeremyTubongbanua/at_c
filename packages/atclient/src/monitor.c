#include "atclient/monitor.h"
#include "atclient/atclient.h"
#include "atclient/atclient_utils.h"
#include "atclient/atnotification.h"
#include "atclient/connection.h"
#include "atclient/constants.h"
#include "atclient/encryption_key_helpers.h"
#include "atclient/string_utils.h"
#include <atchops/aes.h>
#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atchops/platform.h>
#include <atchops/uuid.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "atclient_monitor"

static int parse_message(char *original, size_t original_len, char **message_type, char **message_body);
static int parse_notification(atclient_atnotification *notification, const char *messagebody);
static int decrypt_notification(atclient *monitor_conn, atclient_atnotification *notification);

void atclient_monitor_response_init(atclient_monitor_response *message) {
  memset(message, 0, sizeof(atclient_monitor_response));
}

void atclient_monitor_response_free(atclient_monitor_response *message) {
  if (message->type == ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION) {
    atclient_atnotification_free(&(message->notification));
  } else if (message->type == ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE) {
    free(message->data_response);
  } else if (message->type == ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE) {
    free(message->error_response);
  }
}

void atclient_monitor_init(atclient *monitor_conn) { atclient_init(monitor_conn); }
void atclient_monitor_free(atclient *monitor_conn) { atclient_free(monitor_conn); }

int atclient_monitor_pkam_authenticate(atclient *monitor_conn, const char *atsign, const atclient_atkeys *atkeys,
                                       atclient_authenticate_options *options) {
  int ret = 1;

  if ((ret = atclient_pkam_authenticate(monitor_conn, atsign, atkeys, options, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_monitor_set_read_timeout(atclient *monitor_conn, const int timeoutms) {
  atclient_set_read_timeout(monitor_conn, timeoutms);
}

int atclient_monitor_start(atclient *monitor_conn, const char *regex) {
  int ret = 1;

  size_t cmdsize = 0;
  char *cmd = NULL;

  const size_t regexlen = strlen(regex);

  // log building command... (Debug)
  // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Building monitor command...\n");

  // 2. build cmd
  cmdsize += 7 + 2; // monitor + \r\n
  if (regexlen > 0) {
    cmdsize += regexlen + 1; // $regex + ' '
  }
  cmdsize += 1; // null terminator
  cmd = malloc(sizeof(char) * cmdsize);
  memset(cmd, 0, sizeof(char) * cmdsize);
  const size_t cmdlen = cmdsize - 1;

  if (regexlen > 0) {
    snprintf(cmd, cmdsize, "monitor %.*s\r\n", (int)regexlen, regex);
  } else {
    snprintf(cmd, cmdsize, "monitor\r\n");
  }

  monitor_conn->async_read = true;

  ret = atclient_connection_send(&monitor_conn->atserver_connection, (unsigned char *)cmd, cmdlen, NULL, 0, NULL);
  // 3. send monitor cmd
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send monitor command: %d\n", ret);
    goto exit;
  }
  atlogger_fix_stdout_buffer(cmd, cmdsize);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sSENT: %s\"%.*s\"%s\n", BBLK, HCYN, (int)strlen(cmd), cmd,
               ATCLIENT_RESET);

  ret = 0;
  goto exit;
exit: {
  free(cmd);
  return ret;
}
}

int atclient_monitor_read(atclient *monitor_conn, atclient *atclient, atclient_monitor_response *message,
                          atclient_monitor_hooks *hooks) {

  unsigned char *buffer = NULL;
  size_t buffer_len;

  int ret = atclient_tls_socket_read(&monitor_conn->atserver_connection._socket, &buffer, &buffer_len,
                                     atclient_socket_read_until_char('\n'));

  if (ret == ATCLIENT_SSL_TIMEOUT_EXITCODE) {
    // treat a timeout as empty message, non error
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_EMPTY;
    ret = 0;
    goto exit;
  } else if (ret != 0) { // you should reconnect...
    message->type = ATCLIENT_MONITOR_ERROR_READ;
    message->error_read.error_code = ret;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Error: monitor exited with code %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sRECV: %s\"%.*s\"%s\n", BMAG, HMAG, buffer_len, buffer,
               ATCLIENT_RESET);

  char *messagetype = NULL;
  char *messagebody = NULL;
  ret = parse_message((char *)buffer, buffer_len, &messagetype, &messagebody);
  if (ret != 0) {
    message->type = ATCLIENT_MONITOR_ERROR_PARSE_NOTIFICATION;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Failed to find message type and message body from: %s\n", buffer);
    goto exit;
  }

  if (strcmp(messagetype, "notification") == 0) {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION;
    atclient_atnotification_init(&(message->notification));
    if ((ret = parse_notification(&(message->notification), messagebody)) != 0) {
      message->type = ATCLIENT_MONITOR_ERROR_PARSE_NOTIFICATION;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse notification with messagebody: \"%s\"\n",
                   messagebody);
      goto exit;
    }
    if (atclient_atnotification_is_is_encrypted_initialized(&(message->notification)) &&
        message->notification.is_encrypted == true) {
      // if key contains \"shared_key\", could be in the middle of string, ignore it
      if (strstr(message->notification.key, "shared_key") != NULL) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Ignoring shared_key\n");
        ret = 0;
        goto exit;
      }

      if (hooks != NULL && hooks->pre_decrypt_notification != NULL) {
        ret = hooks->pre_decrypt_notification();
        if (ret != 0) {
          message->type = ATCLIENT_MONITOR_ERROR_DECRYPT_NOTIFICATION;
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to run pre_decrypt_notification hook\n");
          goto exit;
        }
      }

      ret = decrypt_notification(atclient, &(message->notification));

      if (hooks != NULL && hooks->post_decrypt_notification != NULL) {
        ret = hooks->post_decrypt_notification(ret);
        if (ret != 0) {
          message->type = ATCLIENT_MONITOR_ERROR_DECRYPT_NOTIFICATION;
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to run post_decrypt_notification hook\n");
          goto exit;
        }
      }

      if (ret != 0) {
        message->type = ATCLIENT_MONITOR_ERROR_DECRYPT_NOTIFICATION;
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decrypt notification\n");
        goto exit;
      }
    } else {
      atclient_atnotification_set_decrypted_value(&(message->notification), message->notification.value);
    }
  } else if (strcmp(messagetype, "data") == 0) {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE;
    message->data_response = malloc(strlen(messagebody) + 1);
    strcpy(message->data_response, messagebody);
  } else if (strcmp(messagetype, "error") == 0) {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE;
    message->error_response = malloc(strlen(messagebody) + 1);
    strcpy(message->error_response, messagebody);
  } else {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_NONE;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to identify message type from \"%s\"\n", buffer);
    ret = -1;
    goto exit;
  }
  ret = 0;
  goto exit;
exit: {
  free(buffer);
  return ret;
}
}

bool atclient_monitor_is_connected(atclient *monitor_conn) {
  return atclient_connection_is_connected(&monitor_conn->atserver_connection);
}

// given a string notification (*original is assumed to JSON parsable), we can deduce the message_type (e.g. data,
// error, notification) and return the message body which is everything after the prefix (data:, error:, notification:).
// This function will modify *message_type and *message_body to point to the respective values in *original.
static int parse_message(char *original, size_t original_len, char **message_type, char **message_body) {
  int ret = -1;
  char *temp = NULL;
  char *saveptr;

  size_t read_i;
  ret = atclient_utils_find_index_past_at_prompt((unsigned char *)original, original_len, &read_i);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Failed to parse the message: %.*s\n", original_len, original);
    goto exit;
  }
  original = original + read_i;
  original_len = original_len - read_i;
  original[original_len - 1] = '\0';

  // Parse the message type (everything before ':')
  temp = strtok_r(original, ":", &saveptr);
  if (temp == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse message type\n");
    goto exit;
  }
  *message_type = temp;

  // The rest of the string is the message body (JSON in this case)
  temp = strtok_r(NULL, "", &saveptr); // Use an empty delimiter to get the rest of the string
  if (temp == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse message body\n");
    goto exit;
  }
  *message_body = temp;

  // Trim leading whitespace or newlines from message_body
  while (**message_body == ' ' || **message_body == '\n') {
    (*message_body)++;
  }

  // Trim trailing whitespace or newlines from message_body
  size_t trail = strlen(*message_body);
  while (trail > 0 && ((*message_body)[trail - 1] == ' ' || (*message_body)[trail - 1] == '\n')) {
    (*message_body)[--trail] = '\0';
  }

  ret = 0;

exit:
  return ret;
}

// populates *notification given a notification "*messagebody" which has been received from atServer
static int parse_notification(atclient_atnotification *notification, const char *messagebody) {
  int ret = -1;

  if ((ret = atclient_atnotification_from_json_str(notification, messagebody)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse notification from JSON string\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

// after calling `parse_notification`, the *notification struct will be partially filled, all that is left to do is
// decrypt notification->value and put the result in notification->decrypted_value
static int decrypt_notification(atclient *atclient, atclient_atnotification *notification) {
  int ret = 1;

  if (atclient == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    return ret;
  }

  if (notification == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "notification is NULL\n");
    return ret;
  }

  char *from_atsign = NULL;

  unsigned char *decryptedvaluetemp = NULL;

  // holds encrypted value but in raw bytes (after base64 decode operation)
  const size_t ciphertextsize = (strlen(notification->value) + 15) / 16 * 16;
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  // holds shared encryption key in raw bytes (after base64 decode operation)
  const size_t sharedenckeysize = ATCHOPS_AES_256 / 8;
  unsigned char sharedenckey[sharedenckeysize];

  // temporarily holds the shared encryption key in base64
  const size_t sharedenckeybase64size = atchops_base64_encoded_size(sharedenckeysize);
  unsigned char sharedenckeybase64[sharedenckeybase64size];
  memset(sharedenckeybase64, 0, sizeof(unsigned char) * sharedenckeybase64size);

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];

  // 1. make sure everything we need is there

  // 1a. check if value is initialized
  if (!atclient_atnotification_is_value_initialized(notification)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Value is not initialized. Nothing was found to decrypt.\n");
    goto exit;
  }

  if (!atclient_atnotification_is_from_initialized(notification) && notification->from != NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "From field is not initialized\n");
    goto exit;
  }

  // 1b. some warnings
  if (!atclient_atnotification_is_is_encrypted_initialized(notification)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                 "is_encrypted field was found to be uninitialized, we don't know for sure if we're decrypting "
                 "something that's even encrypted.\n");
  } else {
    if (!notification->is_encrypted) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                   "is_encrypted is false, we may be trying to decrypt some unencrypted plain text.\n");
    }
  }

  // 1c. get atsign with @
  if ((ret = atclient_string_utils_atsign_with_at(notification->from, &from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get atsign with @\n");
    goto exit;
  }

  // 2. get iv
  if (atclient_atnotification_is_iv_nonce_initialized(notification) &&
      !atclient_string_utils_starts_with(notification->iv_nonce, "null")) {
    size_t ivlen;
    ret = atchops_base64_decode((unsigned char *)notification->iv_nonce, strlen(notification->iv_nonce), iv,
                                ATCHOPS_IV_BUFFER_SIZE, &ivlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decode iv\n");
      goto exit;
    }

    if (ivlen != ATCHOPS_IV_BUFFER_SIZE) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid iv length was decoded. Expected %d but got %d\n",
                   ATCHOPS_IV_BUFFER_SIZE, ivlen);
      goto exit;
    }
  } else {
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE); // legacy IV
  }

  // 3. get shared encryption key to decrypt
  if ((ret = atclient_get_shared_encryption_key_shared_by_other(atclient, from_atsign, sharedenckey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get shared encryption key\n");
    goto exit;
  }

  // 4. decrypt value
  ret = atchops_base64_decode((unsigned char *)notification->value, strlen(notification->value), ciphertext,
                              ciphertextsize, &ciphertextlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decode value\n");
    goto exit;
  }

  const size_t decryptedvaluetempsize = ciphertextlen + 1;
  decryptedvaluetemp = malloc(sizeof(unsigned char) * decryptedvaluetempsize);
  if (decryptedvaluetemp == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for decrypted value\n");
    goto exit;
  }
  memset(decryptedvaluetemp, 0, sizeof(unsigned char) * decryptedvaluetempsize);
  size_t decryptedvaluetemplen = 0;

  ret = atchops_aes_ctr_decrypt(sharedenckey, ATCHOPS_AES_256, iv, ciphertext, ciphertextlen, decryptedvaluetemp,
                                decryptedvaluetempsize, &decryptedvaluetemplen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decrypt value\n");
    goto exit;
  }

  // 5. set decrypted value
  atclient_atnotification_set_decrypted_value(notification, (const char *)decryptedvaluetemp);

  ret = 0;
  goto exit;
exit: {
  free(decryptedvaluetemp);
  return ret;
}
}
