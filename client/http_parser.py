from typing import Optional
from dataclasses import dataclass


@dataclass
class Response:
    raw: str
    valid: bool
    content_length: Optional[int]
    body: Optional[str] 
    headers: Optional[dict]
    

    def __str__(self):
        txt = f"[*] {'Valid' if self.valid else 'Invalid'} response\n"
        txt += f"{len([] if self.headers is None else self.headers)} headers parsed, content length is {self.content_length}\n\n"
        txt += self.raw
        return txt


def parse_response(response):
    """Parses a string response and returns a Response class."""

    """
    I'm not entirely sure whether the delimiter should be \r\n\r\n, or \n\n.
    Citing RFC2616, 19.3 Tolerant Applications:

    The line terminator for message-header fields is the sequence CRLF. 
    However, we recommend that applications, when parsing such headers, 
    recognize a single LF as a line terminator and ignore the leading CR.
    """
    delimiter = response.find('\r\n\r\n')
    if delimiter == -1:
        delimiter = response.find('\n\n')
    
    if delimiter == -1:
        # Cannot find a delimiter - invalid HTTP request, exiting
        return Response(response, False, None, None, None)

    body = response[delimiter+4:]
    headers_raw = response[:delimiter]

    # Parse raw headers to header -> value pairs
    headers = {}
    for header in headers_raw.split('\n'):
        # Ignore trailing \r
        header = header.strip('\r')

        header_delimiter = header.find(':')
        if header_delimiter == -1:
            continue  # Ignore the invalid header without :

        header_name = header[:header_delimiter]
        header_body = header[header_delimiter+1:]

        # This also ignores duplicate headers, storing the last value
        headers[header_name] = header_body

    try:
        content_length = int(headers['Content-Length'])
    except:
        # Cannot find or parse a Content-Length header - invalid HTTP request, exiting
        return Response(response, False, None, body, headers)

    # We don't check if Content-Length matches, 
    # let's just live in our happy little world without checks
    return Response(response, True, content_length, body, headers)
