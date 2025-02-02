#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atclient/string_utils.h"
#include <atchops/aes.h>
#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atchops/platform.h>
#include <atchops/rsa.h>
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_get_selfkey"

static int atclient_get_self_key_validate_arguments(const atclient *atclient, const atclient_atkey *atkey,
                                                    const char **value);

int atclient_get_self_key(atclient *atclient, atclient_atkey *atkey, char **value,
                          const atclient_get_self_key_request_options *request_options) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_get_self_key_validate_arguments(atclient, atkey, (const char **)value)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_self_key_validate_arguments: %d\n", ret);
    return ret;
  }

  /*
   * 2. Initialize variables
   */
  char *atkey_str = NULL;

  const size_t recv_size = 8192; // TODO use atclient_connection_read to adaptively read for us
  unsigned char recv[recv_size];
  memset(recv, 0, sizeof(unsigned char) * recv_size);
  size_t recv_len = 0;

  const size_t self_encryption_size = ATCHOPS_AES_256 / 8; // 32 byte = 256 bits
  unsigned char self_encryption_key[self_encryption_size];
  memset(self_encryption_key, 0, sizeof(unsigned char) * self_encryption_size);
  size_t self_encryption_key_len = 0;

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];

  // free later
  cJSON *root = NULL;
  char *llookup_cmd = NULL;
  char *value_raw_encrypted = NULL;
  char *value_raw = NULL;
  char *metadata_str = NULL;

  atclient_atkey_metadata metadata;

  /*
   * 3. Build `llookup:` command
   */
  if ((ret = atclient_atkey_to_string(atkey, &atkey_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  const size_t atkey_strlen = strlen(atkey_str);

  const size_t llookup_cmd_size = strlen("llookup:all:\r\n") + atkey_strlen + 1;
  llookup_cmd = (char *)malloc(sizeof(char) * llookup_cmd_size);
  if (llookup_cmd == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for llookup_cmd\n");
    goto exit;
  }
  memset(llookup_cmd, 0, sizeof(char) * llookup_cmd_size);

  snprintf(llookup_cmd, llookup_cmd_size, "llookup:all:%.*s\r\n", (int)atkey_strlen, atkey_str);

  /*
   * 4. Send `llookup:` command
   */
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)llookup_cmd,
                                      llookup_cmd_size - 1, recv, recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Parse response
   */
  char *response = (char *)recv;
  char *response_trimmed = NULL;
  // below method points the response_trimmed variable to the position of 'data:' substring
  if (atclient_string_utils_get_substring_position(response, ATCLIENT_DATA_TOKEN, &response_trimmed) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }
  response_trimmed = response_trimmed + strlen(ATCLIENT_DATA_TOKEN);

  if ((root = cJSON_Parse(response_trimmed)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse: %d\n", ret);
    goto exit;
  }

  cJSON *metadata_json = cJSON_GetObjectItem(root, "metaData");
  if (metadata_json == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  metadata_str = cJSON_Print(metadata_json);

  if ((ret = atclient_atkey_metadata_from_json_str(&metadata, metadata_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_json_str: %d\n", ret);
    goto exit;
  }

  /**
   * 6. Decrypt value
   */
  if (atclient_atkey_metadata_is_iv_nonce_initialized(&metadata)) {
    if ((ret = atchops_base64_decode((unsigned char *)metadata.iv_nonce, strlen(metadata.iv_nonce), iv,
                                     ATCHOPS_IV_BUFFER_SIZE, NULL)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }
  } else {
    // use legacy IV
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  }

  cJSON *data = cJSON_GetObjectItem(root, "data");
  if (data == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_base64_decode((unsigned char *)atclient->atkeys.self_encryption_key_base64,
                                   strlen(atclient->atkeys.self_encryption_key_base64), self_encryption_key,
                                   self_encryption_size, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  // holds base64 decoded value. Once decoded, it is encrypted cipher text bytes that need to be decrypted
  const size_t value_raw_encrypted_size = atchops_base64_decoded_size(strlen(data->valuestring));
  if ((value_raw_encrypted = (char *)malloc(sizeof(char) * value_raw_encrypted_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value_raw\n");
    goto exit;
  }
  memset(value_raw_encrypted, 0, sizeof(char) * value_raw_encrypted_size);
  size_t value_raw_encrypted_len = 0;

  if ((ret = atchops_base64_decode((unsigned char *)data->valuestring, strlen(data->valuestring),
                                   (unsigned char *)value_raw_encrypted, value_raw_encrypted_size,
                                   &value_raw_encrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  const size_t value_raw_size = atchops_aes_ctr_plaintext_size(value_raw_encrypted_len);
  if ((value_raw = (char *)malloc(sizeof(char) * value_raw_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value_raw\n");
    goto exit;
  }
  memset(value_raw, 0, sizeof(char) * value_raw_size);
  size_t value_raw_len = 0;
  if ((ret = atchops_aes_ctr_decrypt(self_encryption_key, ATCHOPS_AES_256, iv, (unsigned char *)value_raw_encrypted,
                                     value_raw_encrypted_len, (unsigned char *)value_raw, value_raw_size,
                                     &value_raw_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_ctr_decrypt: %d\n", ret);
    goto exit;
  }

  if (request_options != NULL &&
      atclient_get_self_key_request_options_is_store_atkey_metadata_initialized(request_options) &&
      request_options->store_atkey_metadata) {
    if ((ret = atclient_atkey_metadata_from_json_str(&atkey->metadata, metadata_str)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_json_str: %d\n", ret);
      goto exit;
    }
  }

  if (value != NULL) {
    const size_t value_len = value_raw_len;
    const size_t value_size = value_len + 1;
    if ((*value = (char *)malloc(sizeof(char) * (value_size))) == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value\n");
      goto exit;
    }
    memcpy(*value, value_raw, value_len);
    (*value)[value_len] = '\0';
  }

  ret = 0;
  goto exit;

exit: {
  if (root != NULL) {
    cJSON_Delete(root);
  }
  free(value_raw);
  free(llookup_cmd);
  free(atkey_str);
  free(value_raw_encrypted);
  free(metadata_str);
  return ret;
}
}

static int atclient_get_self_key_validate_arguments(const atclient *atclient, const atclient_atkey *atkey,
                                                    const char **value) {
  int ret = 1;

  if (atclient == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    goto exit;
  }

  if (!atclient_is_atsign_initialized(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_is_atsign_initialized is false\n");
    goto exit;
  }

  if (!atclient_is_atserver_connection_started(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_is_atserver_connection_started is false\n");
    goto exit;
  }

  if (atclient->async_read) {
    atlogger_log(
        TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
        "atclient_get_self_key cannot be called from an async_read atclient, it will cause a race condition\n");
    return 1;
  }

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized when it should be\n");
    goto exit;
  }

  if (!atclient_atkey_is_shared_by_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.shared_by is not initialized when it should be\n");
    goto exit;
  }

  if (value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value is NULL\n");
    goto exit;
  }

  ret = 0;
exit: { return ret; }
}
