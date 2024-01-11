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

// Not defined in C
// TODO: remove if we move to c++ and use std::min instead
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

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
                            header_delimiter_found = i + x;
                            header_delimiter_size = 2;
                            break;
                        }
                    }

                    if (header_delimiter_found != -1)
                    {
                        break;
                    }
                }
            }

            buffer_at += read_n;
            // Once we found the body, process it in a different loop
            if (header_delimiter_found != -1)
            {
                break;
            }
        }

        // Ensure that we found the headers in the first BUFFER_SIZE bytes
        if (header_delimiter_found == -1)
        {
            printf("Invalid request: limiter was not found in the first %d bytes, closing the connection.\n", BUFFER_SIZE);
            printf("Raw request data:\n>>>>>\n%s\n<<<<<\n", buf);
            close(cfd);
            exit(0);
        }

        printf("Header delimiter was found at pos %d of size %d\n", header_delimiter_found, header_delimiter_size);

        // Copy headers to a separate buffer, we'll reuse buf later on
        char header_buf[BUFFER_SIZE];
        int header_size = header_delimiter_found;
        if (header_size < 0)
        {
            printf("Invalid request: empty header section, closing the connection.\n");
            close(cfd);
            exit(0);
        }

        strncpy(header_buf, buf, header_size);
        printf("\nRaw header data:\n>>>>>\n%s\n<<<<<\n", header_buf);

        // Let's parse our headers
        // We need to copy the buffer, as strtok and strtok_r are DESTRUCTIVE!
        // They replace found delimiters with \0
        char header_buf2[BUFFER_SIZE];
        memcpy(header_buf2, header_buf, BUFFER_SIZE);
        char *method = strtok(header_buf2, " ");
        char *url = strtok(NULL, " ");
        char *version = strtok(NULL, " ");
        int content_length = -1;

        if (method == NULL || url == NULL || version == NULL)
        {
            printf("Invalid request: not found method OR url OR version, closing the connection.\n");
            close(cfd);
            exit(0);
        }

        printf("%s %s %s\n", method, url, version);

        // Our server deals with files on all 4 methods - GET, HEAD, PUT and DELETE
        // For each method the path determines a path to a file
        // I want to prevent directory traversal, and the simplest way to do that is detecting .. in URL
        // Otherwise it's possible (I just tried) to do GET /../../../../../../../../etc/passwd
        // This will of course block some files with double commas in filename,
        // but handling edge cases for proper security is another task of its own
        if (strstr(url, "..") != NULL)
        {
            printf("Invalid request: Path traversal attempt detected, .. found in URL.\n");
            write(cfd, "HTTP/1.1 400 Bad Request\r\n\r\n", 28);
            close(cfd);
            exit(0);
        }

        // Client can not adhere to RFC specs, and send LF instead of CRLF
        // But according to RFC we should handle this case
        // I'll do it this way instead of splitting by \n, to avoid trailing \r
        char *saveptr = NULL;
        char *header = NULL;
        char header_buf3[BUFFER_SIZE];
        memcpy(header_buf3, header_buf, BUFFER_SIZE);
        if (header_delimiter_size == 4)
        {
            // Ignore first line, as it's GET / HTTP1.1
            // Splitting with strtok_r instead of strtok allows us to nest strtoks
            header = strtok_r(header_buf3, "\r\n", &saveptr);
            header = strtok_r(NULL, "\r\n", &saveptr);
        }
        else
        {
            header = strtok_r(header_buf3, "\n", &saveptr);
            header = strtok_r(NULL, "\n", &saveptr);
        }

        printf("\n\nParsing headers...\n");
        while (1)
        {
            if (header == NULL)
            {
                break;
            }
            int header_size = strlen(header);
            if (header_size == 0)
            {
                break;
            }

            // Currently redundant, TODO: check if will be used
            char header_copy[BUFFER_SIZE];
            strncpy(header_copy, header, BUFFER_SIZE);

            // Header now should hold a key:value pair
            // For the sake of simplicity, we're going to assume that there is a single trailing space
            // Though the RFC spec says that there may be 0 or multiple trailing spaces

            char *key = strtok(header_copy, ": ");
            char *value = strtok(NULL, ": ");

            // Parser currently only reads up to first ' ', due to strtok's behaviour
            // TODO: fix this
            // https://stackoverflow.com/questions/60803240/so-strtok-is-destructive
            if (header_delimiter_size == 4)
            {

                header = strtok_r(NULL, "\r\n", &saveptr);
            }
            else
            {
                header = strtok_r(NULL, "\n", &saveptr);
            }

            if (key == NULL || value == NULL)
            {
                printf("Header with NULL key or value, skipping...\n");
                continue;
            }

            if (strcmp(key, "Content-Length") == 0)
            {
                content_length = atoi(value);
            }

            printf("[Header] %s: %s\n", key, value);
        }
        printf("Headers parsed.\n");

        if (strncmp(method, "PUT", 3) == 0 && strlen(method) == 3)
        {
            /*
            RFC 2616:
            For compatibility with HTTP/1.0 applications, HTTP/1.1 requests
            containing a message-body MUST include a valid Content-Length header
            field unless the server is known to be HTTP/1.1 compliant. If a
            request contains a message-body and a Content-Length is not given,
            the server SHOULD respond with 400 (bad request) if it cannot
            determine the length of the message, or with 411 (length required) if
            it wishes to insist on receiving a valid Content-Length.
            */

            // Check if content-length was provided
            if (content_length < 0)
            {
                printf("Invalid request: Content-Length required, closing the connection.\n");
                write(cfd, "HTTP/1.1 411 Length Required\r\n\r\n", 32);
                close(cfd);
                exit(0);
            }

            // Check if content-length is lower than MAXIMUM_CONTENT_LENGTH
            if (content_length > MAXIMUM_CONTENT_LENGTH)
            {
                printf("Invalid request: Content-Length exceeds MAXIMUM-CONTENT-LENGTH '%d', closing the connection.\n", content_length);
                write(cfd, "HTTP/1.1 400 Bad Request\r\n\r\n", 28);
                close(cfd);
                exit(0);
            }
        }

        int IS_GET = strncmp(method, "GET", 3) == 0 && strlen(method) == 3;
        int IS_PUT = strncmp(method, "PUT", 3) == 0 && strlen(method) == 3;
        int IS_HEAD = strncmp(method, "HEAD", 4) == 0 && strlen(method) == 4;
        int IS_DELETE = strncmp(method, "DELETE", 6) == 0 && strlen(method) == 6;

        if (!(IS_GET || IS_PUT || IS_HEAD || IS_DELETE))
        {
            printf("Invalid request: unsupported HTTP method '%s', closing the connection.\n", method);
            write(cfd, "HTTP/1.1 405 Method Not Allowed\r\n\r\n", 35);
            close(cfd);
            exit(0);
        }

        // Concat url parameter to SERVER_RESOURCES_PATH
        char path[strlen(SERVER_RESOURCES_PATH) + strlen(url)];
        strcpy(path, SERVER_RESOURCES_PATH);
        strcat(path, url);

        // Attempt to open file
        char buffer[1024]; // Buffer to store data
        FILE *file = fopen(path, "r");

        // GET, HEAD, and DELETE methods require our file to exist
        if (IS_GET || IS_HEAD || IS_DELETE)
        {
            if (!file)
            {
                printf("Invalid request: Resource '%s' was not found, closing the connection.\n", url);
                write(cfd, "HTTP/1.1 404 Not found\r\n\r\n", 27);
                close(cfd);
                exit(0);
            }
        }

        // Check if our method is supported
        // We use strncmp and strlen for memory safe comparison
        if (IS_GET)
        {
            printf("GET is supported!\n");

            // If file exists, process it and return in response
            int buffer_size = fread(&buffer, sizeof(char), 1024, file);
            fclose(file);

            // Create response string
            size_t base_headers_length = 81;

            char content_length_header[29];
            sprintf(content_length_header, "Content-Length: %d\r\n", buffer_size);

            char res[base_headers_length + buffer_size];
            strcpy(res, "HTTP/1.1 200 OK\r\n");
            strcat(res, content_length_header);
            strcat(res, "Content-Type: application/octet-stream\r\n\r\n");
            strcat(res, buffer);

            // Send response string
            printf("Attempting to send a response...\n");
            write(cfd, res, base_headers_length + buffer_size);
            printf("Response sent, closing cfd!\n\n");
            close(cfd);

            exit(0);
        }
        else if (IS_PUT)
        {
            printf("PUT is supported!\n");
        }
        else if (IS_HEAD)
        {
            printf("HEAD is supported!\n");

            // If file exists, process it and return in response
            int buffer_size = fread(&buffer, sizeof(char), 1024, file);
            fclose(file);

            // Create response string
            size_t base_headers_length = 81;

            char content_length_header[29];
            sprintf(content_length_header, "Content-Length: %d\r\n", buffer_size);

            char res[base_headers_length];
            strcpy(res, "HTTP/1.1 200 OK\r\n");
            strcat(res, content_length_header);
            strcat(res, "Content-Type: application/octet-stream\r\n\r\n");

            // Send response string
            printf("Attempting to send a response...\n");
            write(cfd, res, base_headers_length);
            printf("Response sent, closing cfd!\n\n");
            close(cfd);

            exit(0);
        }
        else if (IS_DELETE)
        {
            printf("DELETE is supported!\n");
            fclose(file);

            if (remove(path) == 0)
            {
                printf("Resource '%s' has been successfully deleted, closing the connection.\n", path);
                write(cfd, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok", 66);
                close(cfd);
                exit(0);
            }

            printf("Invalid request: Resource '%s' could not be deleted, closing the connection.\n", path);
            write(cfd, "HTTP/1.1 501 Internal server error\r\n\r\n", 38);
            close(cfd);
            exit(0);
        }

        // Let's use a dynamic buffer for storing the body content.
        //
        // In our use-case, we could pipe the body content straight into a file,
        // as we're only dealing with it on a PUT request, which should create a file.
        // It would take less RAM, but creating a dynamic buffer is more flexible.
        char *body_buf;
        size_t body_buf_size = 0;
        FILE *body_stream;

        body_stream = open_memstream(&body_buf, &body_buf_size);

        // There can still be some body data left in buf! Let's read it.
        // Determine position of first byte of body in buf
        int existing_body_start_pos = header_delimiter_found + header_delimiter_size;
        // Check how many bytes we can still read from buf
        int existing_body_size = buffer_at - existing_body_start_pos;

        // Check if body_size matches content-length header
        /*
        RFC 2616:
        When a Content-Length is given in a message where a message-body is
        allowed, its field value MUST exactly match the number of OCTETs in
        the message-body. HTTP/1.1 user agents MUST notify the user when an
        invalid length is received and detected.
        */
        if (existing_body_size != content_length)
        {
            printf("Invalid request: Body size is different than Content-Length header '%d', closing the connection.\n", existing_body_size);
            write(cfd, "HTTP/1.1 400 Bad Request\r\n\r\n", 28);
            close(cfd);
            exit(0);
        }

        if (existing_body_size > 0)
        {
            // Get pointer to the first byte of body
            char *existing_body_pointer = buf + existing_body_start_pos;
            // Read it to our dynamic body buffer
            fwrite(existing_body_pointer, existing_body_size, 1, body_stream);
            // Flush our body stream
            fflush(body_stream);
        }

        // If "Expect: 100-continue" header exists, we need to send a 100 Continue response
        // This is used for transmitting files
        char *continue100 = "\nExpect: 100-continue";
        if (strstr(header_buf, continue100) != NULL)
        {
            write(cfd, "HTTP/1.1 100 Continue\r\n\r\n", 25);
            printf("100 Continue sent due to Except: 100-continue header.\n");
        }

        // We can now read remaining data.
        printf("\nReading body bytes:");
        while (1)
        {
            // Read body
            read_n = read(cfd, buf, BUFFER_SIZE);
            printf(" %d", read_n);

            // No bytes left to read? Exit the loop
            if (read_n <= 0)
            {
                break;
            }

            fwrite(buf, read_n, 1, body_stream);
        }
        printf("...done\n");
        fflush(body_stream);

        if (body_buf_size > 0)
        {
            printf("\nRaw body data:\n>>>>>\n%s\n<<<<<\n", body_buf);
        }
        else
        {
            printf("\nEmpty body.\n");
        }

        // Free resources
        fclose(body_stream);
        free(body_buf);

        // TODO: read body limited to Content-Length
        // TODO: appropriate function calls
        // TODO: generate response

        // For now, we'll just ignore the body

        printf("Attempting to send a response...\n");
        // Temporary 200 OK as an universal response
        write(cfd, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok", 66);

        printf("Response sent, closing cfd!\n\n");
        close(cfd);
        exit(0);
    }
    close(sfd);
}