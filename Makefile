PYTHON_CFLAGS=`python-config --cflags`

all: pymovex.so

pymovex.so: pymovex.c
	gcc -shared $(PYTHON_CFLAGS) -o pymovex.so pymovex.c -L. -lMvxSock
