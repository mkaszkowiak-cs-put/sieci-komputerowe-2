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

#define BUFFER_SIZE 1024

/*
void write_xd(int fd, const void *buf, size_t liczba) {
    printf("Attempting to write '%s'\n", buf);
    int bytes_left = liczba;
    int read_bytes = 0;
    int r;
    while (read_bytes < liczba) {
        r = write(fd, buf, liczba);
        if (r <= 0) {
            printf("exiting loop\n");
            break;
        }
        printf("Sent out %d bytes\n", r);
        read_bytes += r;
        bytes_left -= r;
    }
    printf("Sent out the message!\n");
}
doesnt work for some reason
*/

int main(int argc, char **argv)
{
    socklen_t sl;
    int sfd, cfd, on = 1;
    struct sockaddr_in saddr, caddr;

    // disable output buffering
    setbuf(stdout, NULL);

    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(1234);
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    bind(sfd, (struct sockaddr *)&saddr, sizeof(saddr));
    listen(sfd, 10);

    char buf[BUFFER_SIZE];
    char adam[] = "154020";
    char maciej[] = "151856";

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
                        printf("Found %c instead\n", buf[i]);
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
            // printf("waiting...\n");
            // sleep(10);
            //  make cfd non blocking
            // int status = fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL, 0) | O_NONBLOCK);
            if (strcmp(adam, buf) == 0)
            {
                write(cfd, "Adam\n", 5);
            }
            else if (strcmp(maciej, buf) == 0)
            {
                write(cfd, "Maciej\n", 7);
            }
            else
            {
                write(cfd, "Blad\n", 5);
            }
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