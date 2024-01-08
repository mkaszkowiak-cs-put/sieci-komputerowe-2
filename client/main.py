import eel
import client

@eel.expose
def helloworld():
    print("Hello World!")
    

client.get_homepage()

# Remember that functions must be exposed prior to start
eel.init('web')
eel.start('')
