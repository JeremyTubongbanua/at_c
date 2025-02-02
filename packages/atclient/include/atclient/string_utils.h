#ifndef ATCLIENT_STRINGUTILS_H
#define ATCLIENT_STRINGUTILS_H
#ifdef __cplusplus
extern "C" {
#endif

#include <atchops/platform.h> // IWYU pragma: keep
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief trims leading/trailing whitespace/newline
 *
 * @param string string to read from
 * @param stringlen the length of the string (use strlen(string) if it is null-terminated)
 * @param out the output buffer
 * @param out_size the size of the output buffer that you allocated
 * @param out_len the output length of the output buffer that is actually used
 * @return int 0 on success, non-zero on failure
 */
int atclient_string_utils_trim_whitespace(const char *string, const size_t stringlen, char *out, const size_t out_size,
                                          size_t *out_len);

/**
 * @brief check if string starts with prefix
 *
 * @param string the string to check
 * @param prefix the prefix to check for
 * @return true, if string starts with `prefix`, where `prefix` is a valid substring of `string`
 * @return false, otherwise
 */
bool atclient_string_utils_starts_with(const char *string, const char *prefix);

/**
 * @brief check if string ends with suffix
 *
 * @param string the string to check
 * @param suffix suffix to check for
 * @return true, if string ends with `suffix`, where `suffix` is a valid substring of `string`
 * @return false, otherwise
 */
bool atclient_string_utils_ends_with(const char *string, const char *suffix);

/**
 * @brief locates the position of a substring in a given string
 *
 * @param string the string to check (main-string)
 * @param substring the substring to look for in the main-string
 * @param position where the pointer to the position of substring is stored
 * @return
 */
int atclient_string_utils_get_substring_position(const char *string, const char *substring, char **position);

/**
 * @brief generate a new string with the atsign and the guaranteed @ symbol
 *
 * @param original_atsign the original atsign, assumed to be null-terminated
 * @param output_atsign_with_at_symbol the output atsign with the @ symbol, must be freed by the caller
 * @return int 0 on success
 */
int atclient_string_utils_atsign_with_at(const char *original_atsign, char **output_atsign_with_at_symbol);

/**
 * @brief generate a new string with the atsign and the guaranteed @ symbol
 *
 * @param original_atsign the original atsign, assumed to be null-terminated
 * @param output_atsign_without_at_symbol the output atsign without the @ symbol, must be freed by the caller
 * @return int 0 on success
 */
int atclient_string_utils_atsign_without_at(const char *original_atsign, char **output_atsign_without_at_symbol);

/**
 * @brief get the length of a long if it were converted to a string
 *
 * @param n the long to check the length of
 * @return int the string length
 */
int atclient_string_utils_long_strlen(long n);

/**
 * @brief get the length of an int64_t if it were converted to a string
 *
 * @param n the int64_t to check the length of
 * @return int the string length
 */
int atclient_string_utils_int64_strlen(int64_t n);

#ifdef __cplusplus
}
#endif
#endif
