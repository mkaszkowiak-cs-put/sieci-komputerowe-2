import client
# ---- Tests 
    
def send_request_no_headers() -> str:
    """
    Sends a GET / request without a valid header delimiter.
    """
    payload =  f"GET / HTTP/1.1\r\n"
    payload += f"Host: {client.SERVER_ADDRESS[0]}:{client.SERVER_ADDRESS[1]}\r\n"
    payload += f"Connection: close\r\n"
    payload += "There should be a body, but we forgot an extra CRLF!"

    payload = str.encode(payload)
    return client.send_request(payload)

send_request_no_headers()