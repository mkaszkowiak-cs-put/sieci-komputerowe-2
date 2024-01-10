import socket


# TODO: is .decode() without parameters OK? It decodes into UTF-8 by default, but in reality we're using ASCII.

SERVER_ADDRESS = ('localhost', 2138)

def connect():
    """
    Connects to the server address. Returns a socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(SERVER_ADDRESS)
    return sock

def create_get_request(path):
    """
    Constructs a GET request payload, encoded as a binary sequence.
    """
    payload =  f"GET {path} HTTP/1.1\r\n"
    payload += f"Host: {SERVER_ADDRESS[0]}:{SERVER_ADDRESS[1]}\r\n"
    # Required, as HTTP 1.1 by default should support persistent connections
    payload += f"Connection: close\r\n"
    payload += f"Content-Length: 0\r\n"

    payload += "\r\n"

    return str.encode(payload)

def create_delete_request(path):
    """
    Constructs a DELETE request payload, encoded as a binary sequence.
    """
    payload =  f"DELETE {path} HTTP/1.1\r\n"
    payload += f"Host: {SERVER_ADDRESS[0]}:{SERVER_ADDRESS[1]}\r\n"
    # Required, as HTTP 1.1 by default should support persistent connections
    payload += f"Connection: close\r\n"
    payload += f"Content-Length: 0\r\n"

    payload += "\r\n"

    return str.encode(payload)

def read_socket(sock):
    """
    Reads data from socket until none is returned from recv.

    Returns a decoded response.
    """
    data = b''
    while True:
        buf = sock.recv(1024)
        if not buf:
            break
        data += buf
    
    return data.decode()

def get_homepage():
    """
    Returns the response for GET /
    """
    payload = create_get_request("/movies")
    sock = connect()
    sock.sendall(payload)
    output = read_socket(sock)
    sock.close()
    
    return output

def delete_homepage():
    """
    Returns the response for DELETE /movies
    """
    payload = create_delete_request("/movies")
    sock = connect()
    sock.sendall(payload)
    output = read_socket(sock)
    sock.close()
    
    return output