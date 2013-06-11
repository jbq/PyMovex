PYTHON_CFLAGS=`python-config --cflags`

all: _pymovex.so

_pymovex.so: _pymovex.c
	gcc -shared -fPIC $(PYTHON_CFLAGS) -o _pymovex.so _pymovex.c -lMvxSock
