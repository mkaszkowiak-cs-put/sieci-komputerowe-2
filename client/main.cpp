// client.c

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>

#define BUFFER_SIZE 1024
int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage: app.o <indeks>\n");
        return 1;
    }

    char buf[BUFFER_SIZE];
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(1234);
    struct hostent *addrent = gethostbyname("150.254.32.84");
    memcpy(&saddr.sin_addr.s_addr, addrent->h_addr, addrent->h_length);

    connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
    write(fd, argv[1], sizeof(argv[1]));
    write(fd, "\n", 1);
    //    int rc = read(fd, buf, sizeof(argv[1]));
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
        read_n = read(fd, buf + buffer_at, bytes_to_read);
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

    write(1, buf, buffer_at);
    close(fd);
    return 0;
}