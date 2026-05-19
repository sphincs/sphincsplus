#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/resource.h>

#include "../api.h"

#define SERVER_PORT 5000
#define BUFFER_SIZE 8192
#define DEFAULT_TARGET_IP "192.168.4.85"
#define DEFAULT_CONCURRENT 10
#define DEFAULT_BATCHES 0
#define DEFAULT_BATCH_DELAY_SEC 0
#define CLIENT_SK_PATH "client_sk.bin"
#define CLIENT_LOG_PATH "client.log"

static uint64_t get_time_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static unsigned int parse_uint_env(const char *name, unsigned int def_value) {
    const char *val = getenv(name);
    if (!val || *val == '\0') {
        return def_value;
    }

    char *end = NULL;
    unsigned long parsed = strtoul(val, &end, 10);
    if (!end || *end != '\0' || parsed > UINT_MAX) {
        return def_value;
    }

    return (unsigned int)parsed;
}

static int load_file_exact(const char *path, uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    size_t n = fread(buf, 1, len, f);
    fclose(f);

    if (n != len) {
        return -1;
    }

    return 0;
}

static int send_all(int sock, const uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t sent = send(sock, (const char *)buf + total, (int)(len - total), 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (sent == 0) {
            errno = ECONNRESET;
            return -1;
        }
        total += (size_t)sent;
    }
    return 0;
}

static int recv_all(int sock, uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t recvd = recv(sock, (char *)buf + total, (int)(len - total), 0);
        if (recvd == 0) {
            errno = ECONNRESET;
            return -1;
        }
        if (recvd < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        total += (size_t)recvd;
    }
    return 0;
}

static int send_blob(int sock, const uint8_t *data, uint32_t data_len) {
    uint32_t len_net = htonl(data_len);
    if (send_all(sock, (const uint8_t *)&len_net, sizeof(len_net)) < 0) {
        return -1;
    }
    if (data_len == 0) {
        return 0;
    }
    return send_all(sock, data, data_len);
}

static int recv_blob(int sock, uint8_t *buffer, uint32_t buffer_size, uint32_t *out_len) {
    uint32_t len_net = 0;
    if (recv_all(sock, (uint8_t *)&len_net, sizeof(len_net)) < 0) {
        return -1;
    }

    uint32_t payload_len = ntohl(len_net);
    if (payload_len > buffer_size) {
        errno = EMSGSIZE;
        return -1;
    }

    if (payload_len > 0 && recv_all(sock, buffer, payload_len) < 0) {
        return -1;
    }

    *out_len = payload_len;
    return 0;
}

static void log_result(const char *log_path,
                       int status,
                       uint32_t challenge_len,
                       size_t sig_len,
                       uint64_t elapsed_ms) {
    struct rusage ru;
    double user_ms = 0.0;
    double sys_ms = 0.0;
    long rss_kb = 0;

    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        user_ms = (double)ru.ru_utime.tv_sec * 1000.0 + (double)ru.ru_utime.tv_usec / 1000.0;
        sys_ms = (double)ru.ru_stime.tv_sec * 1000.0 + (double)ru.ru_stime.tv_usec / 1000.0;
        rss_kb = ru.ru_maxrss;
    }

    FILE *f = fopen(log_path, "a");
    if (!f) {
        return;
    }

    fprintf(f,
            "pid=%ld status=%s elapsed_ms=%llu cpu_user_ms=%.3f cpu_sys_ms=%.3f rss_kb=%ld challenge=%u sig=%zu\n",
            (long)getpid(),
            status == 0 ? "OK" : "FAIL",
            (unsigned long long)elapsed_ms,
            user_ms,
            sys_ms,
            rss_kb,
            challenge_len,
            sig_len);
    fclose(f);
}

static int client_session(const char *ip, const uint8_t *sk) {
    int sock = -1;
    struct sockaddr_in server_addr;
    uint8_t challenge[BUFFER_SIZE];
    uint32_t challenge_len = 0;
    uint8_t signature[CRYPTO_BYTES];
    size_t sig_len = 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket failed");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid server IP: %s\n", ip);
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect failed");
        close(sock);
        return 1;
    }

    uint64_t start_ms = get_time_ms();

    if (recv_blob(sock, challenge, BUFFER_SIZE, &challenge_len) < 0) {
        perror("recv() challenge failed");
        close(sock);
        return 1;
    }

    if (crypto_sign_signature(signature, &sig_len, challenge, (size_t)challenge_len, sk) != 0) {
        fprintf(stderr, "Signature failed\n");
        close(sock);
        return 1;
    }

    if (sig_len > UINT32_MAX) {
        fprintf(stderr, "Signature too large: %zu bytes\n", sig_len);
        close(sock);
        return 1;
    }

    if (send_blob(sock, signature, (uint32_t)sig_len) < 0) {
        perror("send() signature failed");
        close(sock);
        return 1;
    }

    close(sock);
    log_result(CLIENT_LOG_PATH, 0, challenge_len, sig_len, get_time_ms() - start_ms);
    return 0;
}

int main(int argc, char *argv[]) {
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    const char *target_ip = getenv("TARGET_IP");
    if (!target_ip || *target_ip == '\0') {
        target_ip = DEFAULT_TARGET_IP;
    }

    unsigned int concurrent_sessions = parse_uint_env("CONCURRENT_SESSIONS", DEFAULT_CONCURRENT);
    unsigned int batches = parse_uint_env("BATCHES", DEFAULT_BATCHES);
    unsigned int batch_delay_sec = parse_uint_env("BATCH_DELAY_SEC", DEFAULT_BATCH_DELAY_SEC);

    if (load_file_exact(CLIENT_SK_PATH, sk, sizeof(sk)) < 0) {
        fprintf(stderr, "Missing %s. Run test_sphincsplus_keygen first.\n", CLIENT_SK_PATH);
        return 1;
    }

    printf("[STRESS TEST] SPHINCS+ Client\n");
    printf("- Target IP: %s\n", target_ip);
    printf("- Concurrent sessions: %u\n", concurrent_sessions);
    printf("- Batches: %u\n", batches);
    printf("- Batch delay: %u sec\n", batch_delay_sec);
    printf("\n");

    unsigned int batch = 1;
    while (batches == 0 || batch <= batches) {
        printf("[BATCH %u/%s] Starting...\n", batch, batches == 0 ? "inf" : "fixed");

        pid_t *pids = calloc(concurrent_sessions, sizeof(pid_t));
        if (!pids) {
            perror("calloc failed");
            return 1;
        }

        uint64_t batch_start = get_time_ms();

        for (unsigned int i = 0; i < concurrent_sessions; i++) {
            pids[i] = fork();
            if (pids[i] < 0) {
                perror("fork failed");
                free(pids);
                return 1;
            } else if (pids[i] == 0) {
                /* Child process */
                exit(client_session(target_ip, sk));
            }
        }

        int failed_count = 0;
        for (unsigned int i = 0; i < concurrent_sessions; i++) {
            int status;
            if (waitpid(pids[i], &status, 0) < 0) {
                perror("waitpid failed");
                free(pids);
                return 1;
            }
            if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                failed_count++;
            }
        }

        uint64_t batch_end = get_time_ms();
        printf("[BATCH %u] Completed in %llu ms, %u/%u succeeded\n",
               batch,
               (unsigned long long)(batch_end - batch_start),
               concurrent_sessions - failed_count, concurrent_sessions);

        free(pids);

        if (batches != 0 && batch >= batches) {
            break;
        }

        if (batch_delay_sec > 0) {
            printf("[DELAY] Waiting %u seconds before next batch...\n", batch_delay_sec);
            sleep(batch_delay_sec);
        }

        batch++;
    }

    return 0;
}