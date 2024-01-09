import socket


SERVER_ADDRESS = ('localhost', 2138)

def connect():
    """
    Connects to the server address. Returns a socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(SERVER_ADDRESS)

    return sock

def read_socket(sock) -> str:
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

def send_request(payload: bytes) -> str:
    sock = connect()
    sock.sendall(payload)
    response = read_socket(sock)
    sock.close()
    return response 
