import eel
import client
import http_parser
import json
import wx

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
def get_homepage(path):
    print(f"Calling GET /{path}")
    response = client.get_homepage(path)
    print(response)

    parsed_response = http_parser.parse_response(response)
    return encode_response(parsed_response)

@eel.expose
def head_homepage(path):
    print(f"Calling HEAD /{path}")
    response = client.head_homepage(path)
    print(response)

    parsed_response = http_parser.parse_response(response)
    return encode_response(parsed_response)

@eel.expose
def delete_homepage(path):
    print(f"Calling DELETE /{path}")
    response = client.delete_homepage(path)
    print(response)

    parsed_response = http_parser.parse_response(response)
    return encode_response(parsed_response)

@eel.expose
def put_homepage(path, *args):
    print(f"Calling PUT /{path}")
    response = client.put_homepage(path, *args)
    print(response)

    parsed_response = http_parser.parse_response(response)
    return encode_response(parsed_response)

@eel.expose
def upload_file_homepage(wildcard="*"):
    # Python handles file dialog and returns path of the selected file
    app = wx.App(None)
    style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
    dialog = wx.FileDialog(None, 'Open', wildcard=wildcard, style=style)
    if dialog.ShowModal() == wx.ID_OK:
        path = dialog.GetPath()
    else:
        path = None
    dialog.Destroy()
    return path

# Remember that functions must be exposed prior to start
eel.init('web')
eel.start('')
