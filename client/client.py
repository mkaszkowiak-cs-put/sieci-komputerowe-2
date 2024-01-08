import socket


SERVER_ADDRESS = ('localhost', 2138)

def connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(SERVER_ADDRESS)
    return sock

def create_get_request(path):
    payload =  f"GET {path} HTTP/1.1\r\n"
    payload += f"Host: {SERVER_ADDRESS[0]}:{SERVER_ADDRESS[1]}\r\n"
    # Required, as HTTP 1.1 by default should support persistent connections
    payload += f"Connection: close\r\n"
    payload += "\r\n"

    return str.encode(payload)

def get_homepage():
    payload = create_get_request("/")
    sock = connect()
    sock.sendall(payload)

    data = b''
    while True:
        buf = sock.recv(1024)
        if not buf:
            break
        data += buf

    sock.close()
    output = data.decode()

    print(output)