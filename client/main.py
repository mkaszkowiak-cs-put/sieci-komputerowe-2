import eel
import client
import http_parser
import json

def encode_response(response: http_parser.Response):
    """
    Accepts a http_parser.Response object.

    Returns a response encoded for GUI to display.
    """

    # I don't know the appropriate way to do this with Eel,
    # so we'll just encode then decode a JSON object
    return json.dumps({
        "code": response.code,
        "raw": response.raw,
        "headers": response.headers,
        "content_length": response.content_length,
        "valid": response.valid,
        "body": response.body,
    })


@eel.expose
def helloworld():
    print("Hello World!")
    
@eel.expose
def get_homepage(args):
    print("Calling GET /")
    response = client.get_homepage(args)
    print(response)

    parsed_response = http_parser.parse_response(response)
    return encode_response(parsed_response)

@eel.expose
def head_homepage(args):
    print("Calling HEAD /movies")
    response = client.head_homepage(args)
    print(response)

    parsed_response = http_parser.parse_response(response)
    return encode_response(parsed_response)

@eel.expose
def delete_homepage(args):
    print("Calling DELETE /movies")
    response = client.delete_homepage(args)
    print(response)

    parsed_response = http_parser.parse_response(response)
    return encode_response(parsed_response)

# TODO: We need a way to send files
# See: https://stackoverflow.com/questions/59143267/python3-js-how-do-i-handle-local-file-uploads-with-eel

# Remember that functions must be exposed prior to start
eel.init('web')
eel.start('')
