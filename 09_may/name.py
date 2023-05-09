class Framework:
    def __init__(self,name):
        self.name = name
    def get_name(self):
        return self.name
    def message(self):
        print("My name is" + self.name)

webdev = [Framework("python-Django"),Framework("python-Flask")]

for dev in webdev:
    dev.message()


