import logging

## Log Record attributes (https://docs.python.org/3/library/logging.html)

#this DEBUG in cap is different than logging.debug
# DEBUG is an constant integer in the backgroud
logging.basicConfig(level=logging.DEBUG)

# creating a log file (run the file)

logging.basicConfig(filename='test.log', level=logging.DEBUG)


def add(x, y):
    """add function """
    return x+y

x = 10
y = 5


add_result = add(x,y)
#this debug statement will print in the console
#log files --> great way to capture information bcoz it allows us to see log informations 
logging.debug('Add: {} + {} = {}'.format(x, y,add_result))