import _pymovex

def debug(d):
    _pymovex.debug(d)

def connect(*args, **kwargs):
    return _pymovex.connect(*args, **kwargs)

def fquery(cmd, fieldMap, outputFields=()):
    return _pymovex.fquery(cmd, fieldMap, outputFields)

def fquery_single(cmd, fieldMap, outputFields=()):
    return _pymovex.fquery_single(cmd, fieldMap, outputFields)

def close(*args, **kwargs):
    return _pymovex.close(*args, **kwargs)

def query(cmd, args):
    ffargs=[]
    for value, length in args:
        ffargs.append(("%%-%ss" % length) % value)
    fargs = "".join(ffargs)
    query = "%-15s%s" % (cmd, fargs)
    return _pymovex.query(query)

def rawquery(query):
    return _pymovex.query(query)

def maxrec(num):
    query("SetLstMaxRec", ((num, 11),))
