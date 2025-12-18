#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

static void scan_processes() {
    DIR *d = opendir("/proc");
    struct dirent *ent;

    while ((ent = readdir(d)) != NULL) {
        if (ent->d_type != DT_DIR) continue;
        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        char cmd[256];
        fread(cmd, 1, sizeof(cmd), f);
        fclose(f);

        if (strstr(cmd, "imd")) {
            printf("[Telemetry] IMD-related process PID=%d CMD=%s\n", pid, cmd);
        }
    }
    closedir(d);
}

static void scan_files() {
    if (access("/tmp/important.conf", F_OK) == 0)
        printf("[Telemetry] Detected config modification artifact\n");

    if (access("/tmp/secure_data", F_OK) == 0)
        printf("[Telemetry] Detected sensitive data artifact\n");
}

static void scan_network() {
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) return;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, ":15B3")) {  // 5555 hex
            printf("[Telemetry] Detected internal TCP activity on 127.0.0.1:5555\n");
        }
    }
    fclose(f);
}

int main() {
    printf("[Telemetry] Starting IMD telemetry...\n");

    while (1) {
        scan_processes();
        scan_files();
        scan_network();
        sleep(3);
    }

    return 0;
}
