from distutils.core import setup, Extension
import glob

_pymovex = Extension('_pymovex', sources = ['_pymovex.c'], libraries=['MvxSock'])

setup(name='pymovex',
      version='1.0.4',
      description="Python module for interacting with M3/Movex, implemented using the C-API",
      py_modules=['pymovex'],
      ext_modules=[_pymovex],
      author='Jean-Baptiste Quenot',
      author_email='jbq@caraldi.com',
      url="http://github.com/jbq/pymovex",
      scripts=glob.glob("tests/*")
    )
