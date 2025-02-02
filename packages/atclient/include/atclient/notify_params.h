#ifndef ATCLIENT_NOTIFY_PARAMS_H
#define ATCLIENT_NOTIFY_PARAMS_H
#ifdef __cplusplus
extern "C" {
#endif

#include "atclient/atkey.h"
#include <atchops/platform.h> // IWYU pragma: keep
#include <stdint.h>

#define ATCLIENT_DEFAULT_NOTIFIER "SYSTEM"

#define VALUE_INITIALIZED 0b00000001

#define ATCLIENT_NOTIFY_PARAMS_ID_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_ATKEY_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_VALUE_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_SHOULD_ENCRYPT_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_OPERATION_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_MESSAGE_TYPE_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_PRIORITY_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_STRATEGY_INDEX 0

#define ATCLIENT_NOTIFY_PARAMS_LATEST_N_INDEX 1
#define ATCLIENT_NOTIFY_PARAMS_NOTIFIER_INDEX 1
#define ATCLIENT_NOTIFY_PARAMS_NOTIFICATION_EXPIRY_INDEX 1
#define ATCLIENT_NOTIFY_PARAMS_SHARED_ENCRYPTION_KEY_INDEX 1

#define ATCLIENT_NOTIFY_PARAMS_ID_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_NOTIFY_PARAMS_ATKEY_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_NOTIFY_PARAMS_VALUE_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATCLIENT_NOTIFY_PARAMS_SHOULD_ENCRYPT_INITIALIZED (VALUE_INITIALIZED << 3)
#define ATCLIENT_NOTIFY_PARAMS_OPERATION_INITIALIZED (VALUE_INITIALIZED << 4)
#define ATCLIENT_NOTIFY_PARAMS_MESSAGE_TYPE_INITIALIZED (VALUE_INITIALIZED << 5)
#define ATCLIENT_NOTIFY_PARAMS_PRIORITY_INITIALIZED (VALUE_INITIALIZED << 6)
#define ATCLIENT_NOTIFY_PARAMS_STRATEGY_INITIALIZED (VALUE_INITIALIZED << 7)

#define ATCLIENT_NOTIFY_PARAMS_LATEST_N_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_NOTIFY_PARAMS_NOTIFIER_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_NOTIFY_PARAMS_NOTIFICATION_EXPIRY_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATCLIENT_NOTIFY_PARAMS_SHARED_ENCRYPTION_KEY_INITIALIZED (VALUE_INITIALIZED << 3)

// default param values for atclient_notify_params
#define ATCLIENT_NOTIFY_PARAMS_DEFAULT_NOTIFICATION_EXPIRY 24 * 60 * 60 * 1000 // 24 Hours in Milliseconds
#define ATCLIENT_NOTIFY_PARAMS_DEFAULT_LATEST_N 1
#define ATCLIENT_NOTIFY_PARAMS_DEFAULT_SHOULD_ENCRYPT true
#define ATCLIENT_NOTIFY_PARAMS_DEFAULT_OPERATION ATCLIENT_NOTIFY_OPERATION_NONE
#define ATCLIENT_NOTIFY_PARAMS_DEFAULT_MESSAGE_TYPE ATCLIENT_NOTIFY_MESSAGE_TYPE_KEY
#define ATCLIENT_NOTIFY_PARAMS_DEFAULT_PRIORITY ATCLIENT_NOTIFY_PRIORITY_LOW
#define ATCLIENT_NOTIFY_PARAMS_DEFAULT_STRATEGY ATCLIENT_NOTIFY_STRATEGY_ALL

enum atclient_notify_operation {
  ATCLIENT_NOTIFY_OPERATION_NONE,
  ATCLIENT_NOTIFY_OPERATION_UPDATE,
  ATCLIENT_NOTIFY_OPERATION_DELETE
};

enum atclient_notify_message_type {
  ATCLIENT_NOTIFY_MESSAGE_TYPE_NONE,
  ATCLIENT_NOTIFY_MESSAGE_TYPE_KEY,
  ATCLIENT_NOTIFY_MESSAGE_TYPE_TEXT
};

enum atclient_notify_priority {
  ATCLIENT_NOTIFY_PRIORITY_NONE,
  ATCLIENT_NOTIFY_PRIORITY_LOW,
  ATCLIENT_NOTIFY_PRIORITY_MEDIUM,
  ATCLIENT_NOTIFY_PRIORITY_HIGH
};

enum atclient_notify_strategy {
  ATCLIENT_NOTIFY_STRATEGY_NONE,
  ATCLIENT_NOTIFY_STRATEGY_ALL,
  ATCLIENT_NOTIFY_STRATEGY_LATEST
};

typedef struct atclient_notify_params {
  char *id;
  atclient_atkey *atkey;
  char *value;
  bool should_encrypt;
  enum atclient_notify_operation operation;
  enum atclient_notify_message_type message_type;
  enum atclient_notify_priority priority;
  enum atclient_notify_strategy strategy;
  int64_t latest_n;
  char *notifier;
  int64_t notification_expiry;
  unsigned char *shared_encryption_key;

  uint8_t _initialized_fields[2];
} atclient_notify_params;

void atclient_notify_params_init(atclient_notify_params *params);
void atclient_notify_params_free(atclient_notify_params *params);

bool atclient_notify_params_is_id_initialized(const atclient_notify_params *params);
bool atclient_notify_params_is_atkey_initialized(const atclient_notify_params *params);
bool atclient_notify_params_is_value_initialized(const atclient_notify_params *params);
bool atclient_notify_params_is_should_encrypt_initialized(const atclient_notify_params *params);
bool atclient_notify_params_is_operation_initialized(const atclient_notify_params *params);
bool atclient_notify_params_is_message_type_initialized(const atclient_notify_params *params);
bool atclient_notify_params_is_priority_initialized(const atclient_notify_params *params);
bool atclient_notify_params_is_strategy_initialized(const atclient_notify_params *params);
bool atclient_notify_params_is_latest_n_initialized(const atclient_notify_params *params);
bool atclient_notify_params_is_notifier_initialized(const atclient_notify_params *params);
bool atclient_notify_params_is_notification_expiry_initialized(const atclient_notify_params *params);
bool atclient_notify_params_is_shared_encryption_key_initialized(const atclient_notify_params *params);

void atclient_notify_params_set_id_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_atkey_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_value_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_should_encrypt_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_operation_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_message_type_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_priority_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_strategy_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_latest_n_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_notifier_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_notification_expiry_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_shared_encryption_key_initialized(atclient_notify_params *params,
                                                                  const bool initialized);

int atclient_notify_params_set_id(atclient_notify_params *params, const char *id);
int atclient_notify_params_set_atkey(atclient_notify_params *params, const atclient_atkey *atkey);
int atclient_notify_params_set_value(atclient_notify_params *params, const char *value);
int atclient_notify_params_set_should_encrypt(atclient_notify_params *params, const bool should_encrypt);
int atclient_notify_params_set_operation(atclient_notify_params *params,
                                         const enum atclient_notify_operation operation);
int atclient_notify_params_set_message_type(atclient_notify_params *params,
                                            const enum atclient_notify_message_type message_type);
int atclient_notify_params_set_priority(atclient_notify_params *params, const enum atclient_notify_priority priority);
int atclient_notify_params_set_strategy(atclient_notify_params *params, const enum atclient_notify_strategy strategy);
int atclient_notify_params_set_latest_n(atclient_notify_params *params, const int64_t latest_n);
int atclient_notify_params_set_notifier(atclient_notify_params *params, const char *notifier);
int atclient_notify_params_set_notification_expiry(atclient_notify_params *params, const int64_t notification_expiry);
int atclient_notify_params_set_shared_encryption_key(atclient_notify_params *params,
                                                     const unsigned char *shared_encryption_key);

void atclient_notify_params_unset_id(atclient_notify_params *params);
void atclient_notify_params_unset_atkey(atclient_notify_params *params);
void atclient_notify_params_unset_value(atclient_notify_params *params);
void atclient_notify_params_unset_should_encrypt(atclient_notify_params *params);
void atclient_notify_params_unset_operation(atclient_notify_params *params);
void atclient_notify_params_unset_message_type(atclient_notify_params *params);
void atclient_notify_params_unset_priority(atclient_notify_params *params);
void atclient_notify_params_unset_strategy(atclient_notify_params *params);
void atclient_notify_params_unset_latest_n(atclient_notify_params *params);
void atclient_notify_params_unset_notifier(atclient_notify_params *params);
void atclient_notify_params_unset_notification_expiry(atclient_notify_params *params);
void atclient_notify_params_unset_shared_encryption_key(atclient_notify_params *params);

#ifdef __cplusplus
}
#endif
#endif // ATCLIENT_NOTIFY_PARAMS_H
