#include <atlogger/atlogger.h>
#include <atclient/connection.h>
#include <string.h>

#define TAG "check_docker_readiness"

#define ATSIGN_WITHOUT_AT "alice🛠"

#define VE_ATDIRECTORY_HOST "vip.ve.atsign.zone"
#define VE_ATDIRECTORY_PORT 64

int main() {
    int ret = 1;

    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Checking if virtual environment is ready...\n");

    atclient_connection atdirectory;
    atclient_connection_init(&atdirectory, ATCLIENT_CONNECTION_TYPE_ATDIRECTORY);

    const size_t recv_size = 1024;
    unsigned char recv[recv_size];
    memset(recv, 0, recv_size);
    size_t recv_len = 0;

    const size_t host_size = 256;
    char host[host_size];
    memset(host, 0, sizeof(char) * host_size);

    const size_t port_size = 8;
    char port[port_size];
    memset(port, 0, sizeof(char) * port_size);


    // Check if we can connect to root
    if((ret = atclient_connection_connect(&atdirectory, VE_ATDIRECTORY_HOST, VE_ATDIRECTORY_PORT)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect to root atdirectory\n");
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Connected to atDirectory %s:%d\n", VE_ATDIRECTORY_HOST, VE_ATDIRECTORY_PORT);

    // Check if we can send alice
    const char *command = ATSIGN_WITHOUT_AT "\r\n";
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Sending \"%s\" to atDirectory...\n", ATSIGN_WITHOUT_AT);
    if((ret = atclient_connection_send(&atdirectory, command, strlen(ATSIGN_WITHOUT_AT) + 2, recv, recv_size, &recv_len) != 0)) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send alice to root atdirectory\n");
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Sent \"%s\" to atDirectory\n", ATSIGN_WITHOUT_AT);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Received \"%s\" from atDirectory\n", recv);

    // Ensure that response was not "null" string
    if(strcmp((char *)recv, "null") == 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Received \"null\" from atDirectory\n");
        ret = 1;
        goto exit;
    }

    // Check if we can connect to alice

    
    

    // Check if we can talk to alice's atServer

    // Check if we can pkam authenticate to alice's atServer

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Virtual environment is deemed ready\n");

    ret = 0;

exit: {
    return ret;
}
}