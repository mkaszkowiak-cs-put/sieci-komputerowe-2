import client
# ---- Tests 
    
def send_get_request_no_header_delimiter() -> str:
    """
    Sends a GET / request without a valid header delimiter.
    """
    payload =  f"GET / HTTP/1.1\r\n"
    payload += f"Host: {client.SERVER_ADDRESS[0]}:{client.SERVER_ADDRESS[1]}\r\n"
    payload += f"Connection: close\r\n"
    payload += "There could be a body, but we forgot an extra CRLF!"

    payload = str.encode(payload)
    return client.send_request(payload)

def send_get_request_lflf_header_delimiter() -> str:
    """
    Sends a GET / request with LF line delimiters.
    """
    payload =  f"GET / HTTP/1.1\n"
    payload += f"Host: {client.SERVER_ADDRESS[0]}:{client.SERVER_ADDRESS[1]}\n"
    payload += f"Content-Length: 21\n"
    payload += f"Connection: close\n\n"
    payload += "We have a happy body."

    payload = str.encode(payload)
    return client.send_request(payload)

def send_get_request_no_content_length() -> str:
    """
    Sends a GET / request with no content-length.
    """
    payload =  f"GET / HTTP/1.1\n"
    payload += f"Host: {client.SERVER_ADDRESS[0]}:{client.SERVER_ADDRESS[1]}\n"
    payload += f"Connection: close\n\n"
    payload += "We have a happy body, but no Content-Length header."

    payload = str.encode(payload)
    return client.send_request(payload)

def send_get_request_exceed_content_length() -> str:
    """
    Sends a GET / request that exceeds MAXIMUM-CONTENT-LENGTH.
    """
    payload =  f"GET / HTTP/1.1\n"
    payload += f"Host: {client.SERVER_ADDRESS[0]}:{client.SERVER_ADDRESS[1]}\n"
    payload += f"Content-Length: 52428801\n"
    payload += f"Connection: close\n\n"
    payload += "We have a happy body, but Content-Length header exceeds MAX."

    payload = str.encode(payload)
    return client.send_request(payload)

def send_get_request_invalid_content_length() -> str:
    """
    Sends a GET / request with invalid content-length.
    """
    payload =  f"GET / HTTP/1.1\n"
    payload += f"Host: {client.SERVER_ADDRESS[0]}:{client.SERVER_ADDRESS[1]}\n"
    payload += f"Content-Length: 55\n"
    payload += f"Connection: close\n\n"
    payload += "We have a happy body, but invalid Content-Length header."

    payload = str.encode(payload)
    return client.send_request(payload)


send_get_request_no_header_delimiter()
send_get_request_lflf_header_delimiter()
send_get_request_no_content_length()
send_get_request_exceed_content_length()
send_get_request_invalid_content_length()