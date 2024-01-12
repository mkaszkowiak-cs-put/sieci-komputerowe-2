#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define ERROR_CFD(txt, len) \
    write(cfd, txt, len);   \
    close(cfd);             \
    exit(0);

// Typical HTTP servers' header length limit is 4KiB - 8KiB
// We're limiting ours to a single buffer, up to 4096 bytes (4 KiB)
#define BUFFER_SIZE 4096

// Limit requests to 50 MiB to prevent attacks
#define MAXIMUM_CONTENT_LENGTH 1024 * 1024 * 50

// Accept connections on 0.0.0.0:2138
#define SERVER_PORT 2138
#define SERVER_IP INADDR_ANY

// Wait up to 1s, with up to 10 connections waiting to be processed
#define MAX_QUEUED_CONNECTIONS 10
#define SOCKET_TIMEOUT_S 1

// Server resource files path
#define SERVER_RESOURCES_PATH "resources"

void handle_client_connection(int cfd);