#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>

void flag_config_write() {
    int fd = open("/tmp/important.conf", O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) {
        write(fd, "config=true\n", 12);
        close(fd);
    }
}

void flag_hidden_fork() {
    pid_t pid = fork();
    if (pid == 0) {
        sleep(30);
        _exit(0);
    }
}

void flag_internal_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(5555),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    sleep(5);
    close(sock);
}

void flag_external_exec() {
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/echo", "echo", "IMD helper executed", NULL);
        _exit(0);
    }
    wait(NULL);
}

void flag_sensitive_data() {
    int fd = open("/tmp/secure_data", O_WRONLY | O_CREAT, 0600);
    if (fd >= 0) {
        write(fd, "SECRET=XYZ\n", 11);
        close(fd);
    }
}
