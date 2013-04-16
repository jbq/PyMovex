import simplejson
import pymovex
program = "MMS200MI"
CONO = "900"
with open("prefs.json") as f:
    prefs = simplejson.loads(f.read())
pymovex.connect(program, **prefs)

def query(cmd, args):
    ffargs=[]
    for value, length in args:
        ffargs.append(("%%-%ss" % length) % value)
    fargs = "".join(ffargs)
    query = "%-15s%s" % (cmd, fargs)
    pymovex.query(query)

def maxrec(num):
    query("SetLstMaxRec", ((num, 11),))

#query("LstItmByItm", ((CONO, 3),))

maxrec(1000000)
# will not fetch so many items thanks to the use of a generator
for i, result in enumerate(pymovex.fquery("LstItmByItm", {'CONO': CONO}, ('ITDS', 'FUDS', 'ITNO'))):
    print "%-3s"%i, result
    if i==100:
        break

pymovex.close()
