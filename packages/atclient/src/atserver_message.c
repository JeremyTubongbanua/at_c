#include "./atserver_message.h"
#include <stdlib.h>

const char *atserver_message_get_prompt(struct atserver_message message) {
  if (message.buffer == NULL || atserver_message_get_prompt_len(message) == 0) {
    return NULL;
  }
  return message.buffer;
}

const char *atserver_message_get_token(struct atserver_message message) {
  if (message.buffer == NULL || atserver_message_get_token_len(message) == 0) {
    return NULL;
  }

  return message.buffer + message.prompt_len;
}

const char *atserver_message_get_body(struct atserver_message message) {
  if (message.buffer == NULL || atserver_message_get_body_len(message) == 0) {
    return NULL;
  }
  return message.buffer + message.token_len + message.prompt_len;
}

uint8_t atserver_message_get_prompt_len(struct atserver_message message) { return message.prompt_len; }

uint8_t atserver_message_get_token_len(struct atserver_message message) { return message.token_len; }

uint16_t atserver_message_get_body_len(struct atserver_message message) {
  return message.len - message.token_len - message.prompt_len;
}

struct atserver_message atserver_message_parse(char *buffer, uint16_t len) {
  uint16_t prompt_len = 0;
  uint16_t token_len = 0;
  // 0123456789
  // @foo@data:bar

  // find the end of the token
  while (++token_len < len && buffer[token_len] != ':')
    ; // walk to the end of the token section
  if (token_len == len) {
    // Parse error, token not found
    return (struct atserver_message){NULL, 0, 0, 0};
  }

  // parse the prompt len (if prompt exists in buffer)
  if (buffer[0] == '@') {
    prompt_len = token_len;
    while (--prompt_len > 0 && prompt_len != '@')
      ; // walk to the end of the prompt section
    token_len -= prompt_len;

    prompt_len++; // corrected for 0 based indexing
  }

  if (prompt_len > UINT8_MAX || token_len > UINT8_MAX) {
    // Parse error, by specification they should never come close to exceeding UINT8_MAX
    return (struct atserver_message){NULL, 0, 0, 0};
  }

  return (struct atserver_message){buffer, len, prompt_len, token_len};
}

void atserver_message_free(struct atserver_message message) {
  if (message.buffer != NULL)
    free((char *)message.buffer);
}
