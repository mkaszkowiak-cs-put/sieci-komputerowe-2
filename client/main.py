import eel

@eel.expose
def helloworld():
    print("Hello World!")


# Remember that functions must be exposed prior to start
eel.init('web')
eel.start('')
