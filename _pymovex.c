/**
 * This is an example program that show how to use the Movex API Client Interface in
 * the Linux environment.
 * 
 * When you compile/create your own programs and modules use the following commands:
 *
 *  gcc -o TestSock TestSock.c -L. -lMvxSock
 *
 * Note: 
 *
 */
#include <Python.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>

#include "MvxSock.h"

#define LOBYTE(w)           ((unsigned char)(w))
#define HIBYTE(w)           ((unsigned char)(((unsigned short)(w) >> 8) & 0xFF))


SERVER_ID comStruct;
int result;
unsigned long len;
static PyObject *PyMovexError;
char errstr[1024];

PyObject*reportError(char*method, int result) {
    snprintf(errstr, sizeof(errstr), "%s returned error %d: %s", method, result, comStruct.Buff);
    PyErr_SetString(PyMovexError, errstr);
    return NULL;
}

static PyObject *
pymovex_connect(PyObject *self, PyObject *args, PyObject*kwargs)
{
    char* host;
    int port;
    char* user;
    char* passwd;
    char*conoDivi = "";
    char *program;
    static char *kwlist[] = {"program", "host", "port", "user", "passwd"};

   if (! PyArg_ParseTupleAndKeywords(args, kwargs, "ssiss", kwlist, &program, &host, &port, &user, &passwd))
       return NULL;

   /*
    * If FPW is running remote or locally does not matter if you use
    * the host name by which it is known in your network.
    * If only locally on this server you can as well use 127.0.0.1.
    * It might as well be on another AS/400 in which case we write that IP-address
    * or its host name.
    * We name this test-program "MvxSock C-test"
    * We do NOT want encryption (0) so the last argument (CryptKey) is ignored.
    */
   memset(&comStruct, '\0', sizeof(SERVER_ID));

   printf("Connecting with program %s, host %s, port %d, user %s\n", program, host, port, user);

   if((result=MvxSockSetup(&comStruct, host, port, "MvxSock C-test", 0, "NotUsed")))
       return reportError("MvxSockSetup", result);

   if((result=MvxSockInit(&comStruct, conoDivi, user, passwd, program)))
       return reportError("MvxSockInit", result);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject * pymovex_query(PyObject*self, PyObject*args) {
    char recvBuff[1000];
    char *sendBuff;
    int count;

    if (! PyArg_ParseTuple(args, "s", &sendBuff))
        return NULL;

    printf("Query: |%s|\n", sendBuff);

    len=sizeof(recvBuff);
    count=0;

    if((result=MvxSockTrans(&comStruct, sendBuff, recvBuff, &len)))
        return reportError("MvxSockTrans", result);

    printf("Sent %d bytes: %s\n", strlen(sendBuff), sendBuff);
    printf("Got %d bytes: %s\n", strlen(recvBuff), recvBuff);

    while(strncmp(recvBuff, "REP  ", 5)==0) {
        count++;
        len=1000;
        if((result=MvxSockReceive(&comStruct, recvBuff, &len)))
            return reportError("MvxSockReceive", result);

        printf("Got %d bytes: %s\n", strlen(recvBuff), recvBuff);
    }

    printf("Got %d REP-lines.\n", count);

    Py_INCREF(Py_None);
    return Py_None;
}

typedef struct {
    PyObject_HEAD
    char* cmd;
    PyObject * outputFields;
} pymovex_fquery_MyIter;

PyObject* pymovex_fquery_MyIter_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}

PyObject* pymovex_next_result(PyObject* outputFields) {
    PyObject* d = PyDict_New();
    int pos;
    PyObject*key;

    for (pos=0; pos<PyTuple_GET_SIZE(outputFields); pos++) {
        key = PyTuple_GetItem(outputFields, pos);
        char * value = MvxSockGetField(&comStruct, PyString_AsString(PyObject_Str(key)));
        PyObject*pyvalue = PyString_FromString(value);
        Py_INCREF(pyvalue);
        PyDict_SetItem(d, key, pyvalue);
    }

    Py_INCREF(d);
    return d;
}

PyObject* pymovex_fquery_MyIter_iternext(PyObject *self)
{
    pymovex_fquery_MyIter *p = (pymovex_fquery_MyIter *)self;

    if ((result=MvxSockAccess(&comStruct, p->cmd)))
        return reportError("MvxSockAccess", result);

    if (! MvxSockMore(&comStruct)) {
        /* Raising of standard StopIteration exception with empty value. */
        PyErr_SetNone(PyExc_StopIteration);
        printf("No more results\n");
        return NULL;
    }

    return pymovex_next_result(p->outputFields);
}

static PyTypeObject pymovex_fquery_MyIterType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "_pymovex._fquery_MyIter",            /*tp_name*/
    sizeof(pymovex_fquery_MyIter),       /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    0,                         /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,
      /* tp_flags: Py_TPFLAGS_HAVE_ITER tells python to
         use tp_iter and tp_iternext fields. */
    "Internal myiter iterator object.",           /* tp_doc */
    0,  /* tp_traverse */
    0,  /* tp_clear */
    0,  /* tp_richcompare */
    0,  /* tp_weaklistoffset */
    pymovex_fquery_MyIter_iter,  /* tp_iter: __iter__() method */
    pymovex_fquery_MyIter_iternext  /* tp_iternext: next() method */
};

void pymovex_set_fields(PyObject* fieldMap) {
    PyObject *key, *value;
    Py_ssize_t pos = 0;
    while (PyDict_Next(fieldMap, &pos, &key, &value)) {
        char* skey;
        char* svalue;
        // TODO assert key is a string
        skey = PyString_AsString(PyObject_Str(key));
        // Note: value could be an integer, so we have to call str(value) first
        svalue = PyString_AsString(PyObject_Str(value));
        MvxSockSetField(&comStruct, skey, svalue);
        printf("    Field: (%s, %s)\n", skey, svalue);
    }
}

static PyObject * pymovex_fquery(PyObject*self, PyObject*args) {
    PyObject * fieldMap;
    PyObject * outputFields;
    char*cmd;
    pymovex_fquery_MyIter *p;

    if (! PyArg_ParseTuple(args, "sOO", &cmd, &fieldMap, &outputFields))
        return NULL;

    printf("Command: %s\n", cmd);

    pymovex_set_fields(fieldMap);

   p = PyObject_New(pymovex_fquery_MyIter, &pymovex_fquery_MyIterType);
   if (!p) return NULL;

   p->cmd = cmd;
   p->outputFields = outputFields;
   Py_INCREF(p);
   return (PyObject*)p;
}

static PyObject * pymovex_fquery_single(PyObject*self, PyObject*args) {
    PyObject * fieldMap;
    PyObject * outputFields;
    char*cmd;

    if (! PyArg_ParseTuple(args, "sOO", &cmd, &fieldMap, &outputFields))
        return NULL;

    printf("Command: %s\n", cmd);

    pymovex_set_fields(fieldMap);

    if ((result=MvxSockAccess(&comStruct, cmd)))
        return reportError("MvxSockAccess", result);

    return pymovex_next_result(outputFields);
}

static PyObject* pymovex_close(PyObject *self, PyObject* args) {
   if((result=MvxSockClose(&comStruct)))
       return reportError("MvxSockClose", result);

   Py_INCREF(Py_None);
   return Py_None;
}

static PyMethodDef PyMovexMethods[] = {
    {"connect",  (PyCFunction)pymovex_connect, METH_VARARGS|METH_KEYWORDS, "Connect"},
    {"close",  pymovex_close, METH_VARARGS, "Close"},
    {"query",  pymovex_query, METH_VARARGS, "Query"},
    {"fquery",  pymovex_fquery, METH_VARARGS, "Field-based query"},
    {"fquery_single",  pymovex_fquery_single, METH_VARARGS, "Field-based query with only one expected result"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC init_pymovex(void)
{
    PyObject *m;

    m = Py_InitModule("_pymovex", PyMovexMethods);
    if (m == NULL)
        return;

    PyMovexError = PyErr_NewException("_pymovex.Error", NULL, NULL);
    Py_INCREF(PyMovexError);
    PyModule_AddObject(m, "error", PyMovexError);
}
