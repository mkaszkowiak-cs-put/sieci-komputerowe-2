import eel
import client
import http_parser

@eel.expose
def helloworld():
    print("Hello World!")
    
@eel.expose
def get_homepage():
    print("Calling GET /")
    response = client.get_homepage()
    print(response)
    print(http_parser.parse_response(response))

# Remember that functions must be exposed prior to start
eel.init('web')
eel.start('')
