gcc -c -fPIC mytest.cpp -o mytest.o
gcc -shared mytest.o -o libmytest.so