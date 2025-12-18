#include <stdio.h>
#include <unistd.h>
#include "imd_helpers.h"

int main() {
    printf("[IMD Daemon] Starting...\n");

    flag_config_write();
    flag_hidden_fork();
    flag_internal_socket();
    flag_external_exec();
    flag_sensitive_data();

    while (1) {
        printf("[IMD Daemon] Working...\n");
        sleep(5);
    }

    return 0;
}
