import pymovex
program = "CRS610MI"
pymovex.connect(program)

def query(cmd, args):
    ffargs=[]
    for value, length in args:
        ffargs.append(("%%-%ss" % length) % value)
    fargs = "".join(ffargs)
    query = "%-15s%s" % (cmd, fargs)
    pymovex.query(query)

# "LstByGroup"
query("SetLstMaxRec", ((10, 11),))

pymovex.close()
