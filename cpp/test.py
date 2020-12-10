#C++ test
from ctypes import *
mydll = cdll.LoadLibrary("./libmytest.so")
print(vars(mydll))
print(mydll.myFunction())
print(mydll.addFour(2))
