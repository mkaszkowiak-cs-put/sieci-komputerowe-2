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

// Typical HTTP servers' header length limit is 4K - 8K bytes
// We're limiting ours to 4096 bytes
#define BUFFER_SIZE 4096

// Accept connections on 0.0.0.0:2138
#define SERVER_PORT 2138
#define SERVER_IP INADDR_ANY

// Currently unused
#define MAX_CONCURRENT_CONNECTIONS 10

#define MAX_QUEUED_CONNECTIONS 10

int main(int argc, char **argv)
{
    // As our server runs on fork(), let's ignore SIGCHLD to prevent zombie processes
    signal(SIGCHLD, SIG_IGN);

    socklen_t sl;
    int sfd, cfd, on = 1;
    struct sockaddr_in saddr, caddr;

    // Disable output buffering to get real-time debug
    setbuf(stdout, NULL);

    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = SERVER_IP;
    saddr.sin_port = htons(SERVER_PORT);
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    bind(sfd, (struct sockaddr *)&saddr, sizeof(saddr));
    listen(sfd, MAX_QUEUED_CONNECTIONS);

    printf("Listening on port %d\n", SERVER_PORT);

    char buf[BUFFER_SIZE];

    while (1)
    {
        sl = sizeof(caddr);
        cfd = accept(sfd, (struct sockaddr *)&caddr, &sl);
        pid_t pid = fork();

        if (pid == 0)
        {
            close(sfd);
            printf("new connection from %s: %d\n",
                   inet_ntoa((struct in_addr)caddr.sin_addr),
                   ntohs(caddr.sin_port));

            int buffer_at = 0;
            int read_n = 0;
            while (buffer_at < BUFFER_SIZE)
            {
                int bytes_to_read = BUFFER_SIZE;
                // prevent overflow
                printf("Attempting to read %d bytes\n", bytes_to_read);
                if (bytes_to_read + buffer_at > BUFFER_SIZE)
                {
                    bytes_to_read = BUFFER_SIZE - buffer_at;
                    printf("Now attempting to read %d bytes\n", bytes_to_read);
                }
                read_n = read(cfd, buf + buffer_at, bytes_to_read);
                printf("We have read %d bytes\n", read_n);
                if (read_n <= 0)
                {
                    break;
                }
                int newline_found = 0;
                // let's determine if there's \n somewhere
                for (int i = buffer_at; i < buffer_at + read_n; i++)
                {
                    // i'm tired so a safeguard
                    if (i > BUFFER_SIZE)
                    {
                        printf("Attempting to read outside of buffer, breaking\n");
                        break;
                    }
                    if (buf[i] == '\n')
                    {
                        printf("Newline found at byte %d!\n", i);
                        newline_found = 1;
                        break;
                    }
                    else
                    {
                        //    printf("Found %c instead\n", buf[i]);
                    }
                }

                buffer_at += read_n;
                if (newline_found)
                {
                    break;
                }
            }
            printf("It's time to write!\n");
            printf("We have received: '%s'\n", buf);

            // Temporary 200 OK as an universal response
            write(cfd, "HTTP/1.1 200 OK\nContent-Length: 2\nContent-Type: text/plain\n\nok", 62);

            close(cfd);
            exit(0);
        }
        else
        {
            close(cfd);
        }
        // TODO: zombie
    }
    close(sfd);
}