from typing import Optional
from dataclasses import dataclass


@dataclass
class Response:
    raw: str
    valid: bool
    content_length: Optional[int]
    body: Optional[str] 
    headers: Optional[dict]
    headers_raw: Optional[str]
    code: int
    
    def __str__(self):
        txt = f"[*] {'Valid' if self.valid else 'Invalid'} response\n"
        txt += f"{len([] if self.headers is None else self.headers)} headers parsed, content length is {self.content_length}\n\n"
        txt += self.raw
        return txt


def parse_response(response):
    """Parses a string response and returns a Response class."""

    """
    Citing RFC2616, 19.3 Tolerant Applications:

    The line terminator for message-header fields is the sequence CRLF. 
    However, we recommend that applications, when parsing such headers, 
    recognize a single LF as a line terminator and ignore the leading CR.
    """
    delimiter, delimiter_length = response.find('\r\n\r\n'), 4
    if delimiter == -1:
        delimiter, delimiter_length = response.find('\n\n'), 2
    
    if delimiter == -1:
        # Cannot find a delimiter - invalid HTTP request, exiting
        return Response(response, False, None, None, None, None, None)


    body = response[delimiter+delimiter_length:]
    headers_raw = response[:delimiter]
    code = 0

    # Parse raw headers to header -> value pairs
    headers = {}
    for index, header in enumerate(headers_raw.split('\n')):
        # Ignore trailing \r
        header = header.strip('\r')

        if (index == 0):
            code = header.split(" ")[1]

        header_delimiter = header.find(':')
        if header_delimiter == -1:
            continue  # Ignore the invalid header without :

        header_name = header[:header_delimiter]
        header_body = header[header_delimiter+1:].lstrip()

        # This also ignores duplicate headers, storing the last value
        headers[header_name] = header_body

    try:
        content_length = int(headers['Content-Length'])
    except:
        # Cannot find or parse a Content-Length header - invalid HTTP request, exiting
        return Response(response, False, None, body, headers, headers_raw, code)

    # We don't check if Content-Length matches, 
    # let's just live in our happy little world without checks
    # and without trimming the remaining content past Content-Length

    return Response(response, True, content_length, body, headers, headers_raw, code)