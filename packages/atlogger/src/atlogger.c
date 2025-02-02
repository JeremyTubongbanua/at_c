
#include "atlogger/atlogger.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(ATLOGGER_DISABLE_TIMESTAMPS) && !defined(ATLOGGER_OVERRIDE_LOG_FUNCTION)
#include <time.h>
#endif

#define PREFIX_BUFFER_LEN 64
#define INFO_PREFIX "\e[0;32m[INFO]\e[0m"
#define WARN_PREFIX "\e[0;31m[WARN]\e[0m"
#define ERROR_PREFIX "\e[1;31m[ERROR]\e[0m"
#define DEBUG_PREFIX "\e[0;34m[DEBG]\e[0m"

typedef struct atlogger_ctx {
  enum atlogger_logging_level level;
  int opts;
} atlogger_ctx;

static atlogger_ctx ctx;
static int is_ctx_initalized = 0;

static atlogger_ctx *atlogger_get_instance() {
  if (is_ctx_initalized == 0) {
    is_ctx_initalized = 1;
  }
  return &ctx;
}

#ifndef ATLOGGER_OVERRIDE_LOG_FUNCTION
static void atlogger_get_prefix(enum atlogger_logging_level logging_level, char *prefix, size_t prefixlen) {
  memset(prefix, 0, prefixlen);
  int off = 0;

  switch (logging_level) {
  case ATLOGGER_LOGGING_LEVEL_INFO: {
    off = strlen(INFO_PREFIX);
    memcpy(prefix, INFO_PREFIX, off);
    break;
  }
  case ATLOGGER_LOGGING_LEVEL_WARN: {
    off = strlen(WARN_PREFIX);
    memcpy(prefix, WARN_PREFIX, off);
    break;
  }
  case ATLOGGER_LOGGING_LEVEL_ERROR: {
    off = strlen(ERROR_PREFIX);
    memcpy(prefix, ERROR_PREFIX, off);
    break;
  }
  case ATLOGGER_LOGGING_LEVEL_DEBUG: {
    off = strlen(DEBUG_PREFIX);
    memcpy(prefix, DEBUG_PREFIX, off);
    break;
  }
  default: {
    break;
  }
  }

#ifndef ATLOGGER_DISABLE_TIMESTAMPS
  struct timespec timespec;
  int res = clock_gettime(CLOCK_REALTIME, &timespec);

  if (res == 0) {
    res = strftime(prefix + off, PREFIX_BUFFER_LEN - off, " %F %T",
                   gmtime(&timespec.tv_sec)); // format accurate to the second
    if (res != 0) {
      off += res;
      res = 0;
    }
  }
  if (res == 0) {
    snprintf(prefix + off, PREFIX_BUFFER_LEN - off, ".%09lu", timespec.tv_nsec);
    off += strlen(prefix + off);
  }
#endif

  off -= 3;
  snprintf(prefix + off, PREFIX_BUFFER_LEN - off, " |");
  off += 2;
  prefix[off] = '\0';
}
#endif

enum atlogger_logging_level atlogger_get_logging_level() {
  atlogger_ctx *ctx = atlogger_get_instance();
  return ctx->level;
}

void atlogger_set_logging_level(const enum atlogger_logging_level level) {
  atlogger_ctx *ctx = atlogger_get_instance();
  ctx->level = level;
}

void atlogger_set_opts(int opts) {
  atlogger_ctx *ctx = atlogger_get_instance();
  ctx->opts = opts;
}

#ifndef ATLOGGER_OVERRIDE_LOG_FUNCTION
void atlogger_log(const char *tag, const enum atlogger_logging_level level, const char *format, ...) {
  atlogger_ctx *ctx = atlogger_get_instance();

  if (level > ctx->level) {
    return;
  }

  va_list args;
  va_start(args, format);
  if (tag != NULL) {
    char *prefix = malloc(sizeof(char) * PREFIX_BUFFER_LEN);
    if (prefix != NULL) {
      atlogger_get_prefix(level, prefix, PREFIX_BUFFER_LEN);
      printf("%.*s ", (int)strlen(prefix), prefix);
      printf("%.*s | ", (int)strlen(tag), tag);
      free(prefix);
    }
  }
  vprintf(format, args);
  va_end(args);
}
#endif

void atlogger_fix_stdout_buffer(char *str, const size_t strlen) {
  // if str == 'Jeremy\r\n', i want it to be 'Jeremy'
  // if str == 'Jeremy\n', i want it to be 'Jeremy'
  // if str == 'Jeremy\r', i want it to be 'Jeremy'

  if (strlen == 0) {
    goto exit;
  }

  int carriagereturnindex = -1;
  int newlineindex = -1;

  for (int i = strlen - 1; i >= 0; i--) {
    if (str[i] == '\r' && carriagereturnindex == -1) {
      carriagereturnindex = i;
    }
    if (carriagereturnindex != -1 && newlineindex != -1) {
      break;
    }
  }

  if (carriagereturnindex != -1) {
    for (size_t i = carriagereturnindex; i < strlen - 1; i++) {
      str[i] = str[i + 1];
    }
    str[strlen - 1] = '\0';
  }

  for (int i = strlen - 1; i >= 0; i--) {
    if (str[i] == '\n' && newlineindex == -1) {
      newlineindex = i;
    }
    if (carriagereturnindex != -1 && newlineindex != -1) {
      break;
    }
  }

  if (newlineindex != -1) {
    for (size_t i = newlineindex; i < strlen - 1; i++) {
      str[i] = str[i + 1];
    }
    str[strlen - 1] = '\0';
  }

  goto exit;

exit: { return; }
}
