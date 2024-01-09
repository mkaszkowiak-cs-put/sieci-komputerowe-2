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

// Not defined in C
// TODO: remove if we move to c++ and use std::min instead
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// Typical HTTP servers' header length limit is 4KiB - 8KiB
// We're limiting ours to 4096 bytes (4 KiB)
#define BUFFER_SIZE 4096

// Accept connections on 0.0.0.0:2138
#define SERVER_PORT 2138
#define SERVER_IP INADDR_ANY

// Wait up to 1s, with up to 10 connections waiting to be processed
#define MAX_QUEUED_CONNECTIONS 10
#define SOCKET_TIMEOUT_S 1

int main(int argc, char **argv)
{
    // As our server runs on fork(), let's ignore SIGCHLD to prevent zombie processes
    signal(SIGCHLD, SIG_IGN);

    socklen_t sl;
    int sfd, cfd, on = 1;
    struct sockaddr_in saddr, caddr;

    // Disable output buffering to get real-time debug
    setbuf(stdout, NULL);

    // Bind a socket to specified IP:port with up to MAX_QUEUED_CONNECTIONS
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = SERVER_IP;
    saddr.sin_port = htons(SERVER_PORT);
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    bind(sfd, (struct sockaddr *)&saddr, sizeof(saddr));
    listen(sfd, MAX_QUEUED_CONNECTIONS);

    printf("Listening on port %d\n", SERVER_PORT);

    char buf[BUFFER_SIZE];
    // Accept connections in an infinite loop
    while (1)
    {
        sl = sizeof(caddr);
        cfd = accept(sfd, (struct sockaddr *)&caddr, &sl);
        pid_t pid = fork();

        // In main process, close unused cfd descriptor, and wait for the next client
        if (pid != 0)
        {
            close(cfd);
            continue;
        }

        // In child process, close unused sfd descriptor, and process the client
        close(sfd);
        printf("new connection from %s: %d\n",
               inet_ntoa((struct in_addr)caddr.sin_addr),
               ntohs(caddr.sin_port));

        // Set socket timeout:
        int timeout_s = SOCKET_TIMEOUT_S * 1000;
        // 1. Set TCP user Timeout - https://www.rfc-editor.org/rfc/rfc5482
        setsockopt(cfd, 6, 18, (char *)&timeout_s, sizeof(timeout_s));

        // 2. Set write and read timeouts
        struct timeval timeout;
        timeout.tv_sec = SOCKET_TIMEOUT_S;
        timeout.tv_usec = 0;
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        int buffer_at = 0;
        int read_n = 0;
        int header_delimiter_found = -1;
        int header_delimiter_size = 0;
        // Start with reading the header
        // For simplicity, its size can be only up to BUFFER_SIZE (currently 4 KiB)
        while (buffer_at < BUFFER_SIZE)
        {
            // Read to buffer from cfd, up to its maximum size
            int bytes_to_read = MIN(BUFFER_SIZE, BUFFER_SIZE - buffer_at);
            read_n = read(cfd, buf + buffer_at, bytes_to_read);

            // No bytes left to read? Exit the loop
            if (read_n <= 0)
            {
                break;
            }

            // Try to find a header separator
            for (int i = buffer_at; i < buffer_at + read_n - 3; i++)
            {
                // Standard header separator is CRLF CRLF
                if (
                    buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
                {
                    printf("Header delimiter [CRLF CRLF] found at byte %d!\n", i);
                    header_delimiter_found = i;
                    header_delimiter_size = 4;
                    break;
                }
                else
                {
                    // We should also check for \n\n, according to RFC 2616
                    // This won't be most optimal, as we could only do that for the boundaries,
                    // but w/e

                    // The reason for a for loop is that for a single check on a 4-byte region,
                    // we would only check 1 out of 3 possible combinations (XXaa, aXXa, aaXX)
                    for (int x = 0; x < 3; x++)
                    {
                        if (
                            buf[i + x] == '\n' && buf[i + x + 1] == '\n')
                        {
                            printf("Header delimiter [LF LF] found at byte %d!\n", i + x);
                            header_delimiter_found = i + x;
                            header_delimiter_size = 2;
                            break;
                        }
                    }
                }
            }

            buffer_at += read_n;
            // Once we found the body, process it into a different loop
            if (header_delimiter_found != -1)
            {
                break;
            }
        }

        // Ensure that we found the headers in the first BUFFER_SIZE bytes
        if (header_delimiter_found == -1)
        {
            printf("We have received: '%s'\n", buf);
            printf("Invalid request: limiter was not found in the first %d bytes, closing the connection.\n", BUFFER_SIZE);
            close(cfd);
            exit(0);
        }

        // TODO: parse headers
        // TODO: read body according to Content-Length
        // TODO: parse body
        // TODO: appropriate function calls
        // TODO: generate response

        // For now, we'll just ignore the body
        printf("It's time to write!\n");
        printf("We have received: '%s'\n", buf);
        printf("Header delimiter was found at %d with size %d", header_delimiter_found, header_delimiter_size);

        // Temporary 200 OK as an universal response
        write(cfd, "HTTP/1.1 200 OK\nContent-Length: 2\nContent-Type: text/plain\n\nok", 62);

        close(cfd);
        exit(0);
    }
    close(sfd);
}