>>> def true_func():
...     print('Running true_func()')
...     return True
...
>>> def false_func():
...     print('Running false_func()')
...     return False
...
>>> true_func() or false_func()  # Case 1
Running true_func()
True
>>> false_func() or true_func()  # Case 2
Running false_func()
Running true_func()
True
>>> false_func() or false_func()  # Case 3
Running false_func()
Running false_func()
False
>>> true_func() or true_func()  # Case 4
Running true_func()
True