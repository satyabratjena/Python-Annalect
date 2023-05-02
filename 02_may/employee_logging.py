import logging

logging.basicConfig(filename='employee.log', level=logging.INFO,
                    format='%(levelname)s:%(message)s')


class Employee:
    """A sample Employee class"""

#when we create the class Employee, it will create the first name and last name on the instance
    def __init__(self, first, last):
        self.first = first
        self.last = last
        
        # printing it that we have create a employee
        #print('Create Employee: {} - {}'.format(self.fullname, self.email))

        logging.info('Created Employee: {} - {}'.format(self.fullname, self.email))

    @property
    def email(self):
        return '{}.{}@email.com'.format(self.first, self.last)

    @property
    def fullname(self):
        return '{} {}'.format(self.first, self.last)


emp_1 = Employee('John', 'Smith')
emp_2 = Employee('Corey', 'Schafer')
emp_3 = Employee('Jane', 'Doe')