#ifndef ATCLIENT_ATCLIENT_UTILS_H
#define ATCLIENT_ATCLIENT_UTILS_H
#ifdef __cplusplus
extern "C" {
#endif

#include "atclient/atkeys.h"
#include <atchops/platform.h> // IWYU pragma: keep

/**
 * @brief Get address of atServer from the atDirectory, You should check the return code of this function before using
 * any of the output parameters.
 *
 * @param atdirectory_host the host of the atDirectory (e.g. "root.atsign.org")
 * @param atdirectory_port the port of the atDirectory (e.g. 64)
 * @param atsign the null terminated atsign string, doesn't matter if it starts with `@` or not.
 * @param atserver_host the output host of the secondary server, will be null terminated, caller must free this memory
 * @param atserver_port the output port of the secondary server, will be set to 0 if the port is not found
 * @return int 0 on success, non-zero on error
 */
int atclient_utils_find_atserver_address(const char *atdirectory_host, const int atdirectory_port, const char *atsign,
                                         char **atserver_host, int *atserver_port);

/**
 * @brief Populate atkeys from the atkeys file in the home directory of the user.
 *
 * @param atkeys the atkeys struct to populate
 * @param atsign the atsign string, assumed to be null terminated
 * @return int 0 on success, non-zero on error
 */
int atclient_utils_populate_atkeys_from_homedir(atclient_atkeys *atkeys, const char *atsign);

/**
 * @brief find the index of the next character after an atServer / atDirectory's prompt
 *
 * @param read_buf buffer to check
 * @param read_n length of the buffer to check
 * @param read_i output parameter containing the first token after the prompt
 *
 * @return int 0 on success, non-zero on error
 */
int atclient_utils_find_index_past_at_prompt(const unsigned char *read_buf, size_t read_n, size_t *read_i);

#ifdef __cplusplus
}
#endif
#endif // ATCLIENT_UTILS_H
