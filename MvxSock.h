/* DoubleSave: c:\MvxAPI\MvxSock\MvxSock.h
   The above filename is used to save a copy of the file
   in a PC when coding in AS/400 environment.
   Do not move, remove or alter the filename above.
*/

/*---------------------------------------------------------------------*\
| File    : MvxSock.h (Movex TCP/IP Threaded Client Socket Support)
| Created : 11 Dec 1997
|
| Copyright (c) Intentia Research & Development, 1997
\*---------------------------------------------------------------------*/

/*
This file contains some useful functions for handling client
part of sockets under windows NT.

When you get an error code you also get a plaintext message, but here is
a short description if you want your program to try to interpret the error.
Code   Explanation
0      OK (no error)
1      General error on input data (user error)
2      No connection to server exists
3      Recieve buffer is to small (first part of message from server is returned as valid data)
4      No recieve buffer exists
5      Crypto error (internal error. Read plaintext for more details)
6      Illegal type of transaction when calling function.
7      Other error (severe) (must read plaintext message)
8      Error returned from server (must read plaintext message)
11-19  Function specific errors from user input (Specification of error 1)
*/

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
   #ifndef NOMVXSOCKLIB
      #pragma comment(lib, "MvxSock.lib")
   #endif
#else
#define CALLBACK
#define VARARG
#define INVALID_SOCKET -1
#endif

#define F_FIELDACCESS    0x0001
#define F_UCS2           0x0002
#define F_AS400TOJAVA    0x0004 /* Only required in an AS400 client towards NG */
#define F_WIN            0x0008 /* Server is a Windows machine */
#define F_NOIOCTL        0x0010
#define F_ZIPPED         0x0020 /* Only valid under WIN32 */

#ifdef WIN32
   /**
    * MvxSock.dll is compiled with structure packing == 1. To ensure proper member alignment from the
    * client programs we need to use this pragma here. The current packing are saved and restored
    * after the Movex API related structures has been declared.
    * The pragma introduced for version 4.7.
    */
   #pragma pack(push, MvxAPI, 1)
#endif
typedef unsigned int MvxSocket;
typedef unsigned short wchar_u; /* UCS-2 character definition to ensure two-bytes in all environments */

typedef struct _B_FIELD { /* size 344 */
	char name[8];
	char data[328];
	struct _B_FIELD *next;
	char reserved[4];
	} B_FIELD;

typedef struct _FLDMAP { /* size 32 */
   char    szName[16];
   char    reserved[8];
   char    *pMap;
   struct _FLDMAP *pNext;
   } FLDMAP, *PFLDMAP;

typedef struct _SERVER_ID { /* size 440, in AS400 560 */
            char      ServerName[32];
            unsigned short ServerPortNr;
            unsigned short usFlags;
            char      ApplicationName[17];
            char      MessageID[8];
            char      BadField[7];
            char      Buff[256];
            MvxSocket TheSocket;
            int       cryptOn;          /* 4 bytes - Crypto: 1 is on & 0 is off */
            unsigned char cryptKey[57]; /* 57 bytes - Crypto key: maximum 448 bits */
            int       Trim;     /* This position earlier kept the "Mode" variable. */
            int       iNextGen; /* Indicates if we are running against NextGen */
            int       iToken;   /* Holds the token from NextGen*/
            char      *pFld;
            char      *pCurTrans;
            char      *pTrans;
            PFLDMAP   pOut;
            PFLDMAP   pIn;
            B_FIELD   *field;
#if defined(__SUN__) || defined(__AIX__) || defined(__LINUX__)
            iconv_t   toAnsi;    /* In Sun we need to use iconv for Ansi/UCS2 conversion */
            iconv_t   toUCS2;
            char reserved[7];          /* 7 bytes - For future use */
#elif defined(__AS400__)
            iconv_t   *toEbcdic; /* In AS400 we need to use iconv for Ebcdic/UCS2 conversion */
            iconv_t   *toUCS2; /* In AS400 iconv_t is a struct so we use pointers (allocated space) */
            char reserved[7];          /* 7 bytes - For future use */
#else
            unsigned char *zipb;
            char reserved[11];       /* 11 bytes - For future use */
#endif
            } SERVER_ID, *PSERVER_ID;


#ifdef WIN32
   #pragma pack(pop, MvxAPI)
#endif


/**
 * Description: Alternative way of configuring the Sockets communication
 *              where no cfg file is used. Instead the IP-adress and socket port
 *              are given as arguments.
 *
 * Argument: pointer to struct
 *           IP-adress of FPW server
 *           Socket port of FPW
 *           Application name
 *           Encryption on/off
 *           Encryption key
 *
 * Returns: 0 = OK  0 >Error.
 *
 * Remark: Application name are for logging purposes only.
 *         Call MvxSockSetup OR MvxSockConfig before opening connection
 *
 * Example call:
 *       result=MvxSockSetup(TheServerStruct, "10.20.20.238", 6000, "MyTestApp", 0, NULL);
 *
 */
unsigned long CALLBACK MvxSockSetup(PSERVER_ID pstruct, char *WrapperName, int WrapperPort,
                     char *ApplicationName, int cryptOn, char *cryptKey);


/**
 * Description: Load the configuration file. In the cfg-file IP-address
 *              of the FPW server and Socket port are located.
 *
 * Argument: Pointer to PSERVER_ID struct
 *           Namepath of configuration file
 *
 * Returns: 0 = OK  0 > Error.
 *
 * Remark: Call MvxSockConfig OR MvxSockSetup before opening connection
 *
 */
unsigned long CALLBACK MvxSockConfig(PSERVER_ID pstruct, char *ConfigFilename);


/**
 * Initialization function for starting up the communication.
 *
 * Argument: pstruct = Pointer to PSERVER_ID structure
 *           ConoDivi = Optional CONO DIVI parameter
 *           UserId = User Id
 *           UserPwd = Password
 *           AS400program = name of communication program on the AS/400 given
 *                          as "LIBRARY/PGMNAME"
 *
 * Return:   0 = OK, 0 > Error
 *
 * Remark: The function can NOT verify the user and password or the existence of the
 *         given program.
 */
unsigned long CALLBACK MvxSockInit(PSERVER_ID pstruct, char *ConoDivi, char *UserId,
                        char *UserPwd, char *AS400program);


/**
 * Description: Simplified, combined setup and initiation function
 *
 * Argument: pstruct = Pointer to PSERVER_ID structure
 *           UserId = User Id on Movex application server
 *           Pwd = Password
 *           MI = name of MI program on application server given as "LIBRARY/PGMNAME" or "PGMNAME"
 *           Host = IP-adress of application server
 *           Port = Socket port of application server
 *           Key = Encryption key, if not used set it NULL
 *
 * Return:   0 = OK, 0 > Error
 *
 * Remark:
 *
 */
unsigned long CALLBACK MvxSockConnect( PSERVER_ID pstruct, char *Host, int Port,
            char *UserId, char *Pwd, char *MI, char *Key);


/**
 * Description: The transfer function. Transfers a null terminated string
 *              to the program initiated. Layout/protocol of string should
 *              be coordinated with that program.
 *
 * Argument:   Pointer to struct
 *             Pointer to data to be sent.
 *             Pointer to return buffer
 *             Pointer to unsigned long variable to receive returned length
 *               OBS! On entry to the function it should contain the size of return buffer.
 *
 * Return:    0 = OK, 0 > Error
 *
 * Remark:    The wide chars supported are UCS-2, ie two bytes.
 */
unsigned long CALLBACK MvxSockTrans(PSERVER_ID pstruct, char *pSendBuffer,
                           char *pRetBuffer, unsigned long *pulRetLength);
unsigned long CALLBACK MvxSockTransW( PSERVER_ID pstruct, wchar_u *pSendBuffer,
                           wchar_u *pRetBuffer, unsigned long *pulRetLength);

/**
 * Description: The receive functions. Used when more than one record is to be retrieved.
 *              Repeatedly called in a loop. Break loop when OK is received.
 *
 * Argument:    Pointer to struct
 *              Pointer to return buffer
 *              Pointer to unsigned long variable to receive returned length in bytes.
 *               OBS! On entry to the function it should contain the size of return buffer.
 *
 * Return:      0 = OK, 0 > Error
 *
 * Remark:     The wide chars supported are UCS-2, ie two bytes.
 */
unsigned long CALLBACK MvxSockReceive(PSERVER_ID pstruct, char *pRecvBuffer, unsigned long *pulRetLength);
unsigned long CALLBACK MvxSockReceiveW(PSERVER_ID pstruct, wchar_u *pRecvBuffer, unsigned long *pulRetLength);


/**
 * Description: The send function. Used only with transactions beginning with the
 *              letters "Snd". The purpose is to offer a fast way to upload data.
 *              The function does not expect the MI - program to reply on the sent
 *              information. No error information can therefore be returned as well.
 *
 * Argument:    Pointer to struct
 *              Pointer to send buffer (NULL terminated)
 *              Pointer to unsigned long variable with sending length
 *
 * Return:    0 = OK, 0 > Error
 *
 * Remark:     Only certain special transactions support use of this function. You
 *             need to verify in the transaction documentation if this is the case.
 *             The wide chars supported are UCS-2, ie two bytes.
 */
unsigned long CALLBACK MvxSockSend(PSERVER_ID pstruct, char *pSendBuffer);
unsigned long CALLBACK MvxSockSendW(PSERVER_ID pstruct, wchar_u *pSendBuffer);

/**
 *       ***************************************************************
 *       *   OBSOLETE function!!! No longer used in the Send context.  *
 *       ***************************************************************
 *
 * Description: Change mode. Currently only two modes are allowed: normal mode and
 *              multiple sending mode. The multiple sending mode should only be used
 *              when you need to upload lots of data and you get performance problems
 *              if you upload the data with MvxSockTrans().
 *              Allowed modes are: SOCKMODESEND, SOCKMODENORMAL
 *
 */
unsigned long CALLBACK MvxSockSetMode(PSERVER_ID pstruct, int mode, char *pTransName, char *pResult, unsigned long *pulRetLength);


/**
 * Description: Get current MvxSock version
 *
 * Argument: none
 *
 * Returns:  SHORT
 *
 * Remark: Major version in HIBYTE(v), minor in LOBYTE(v)
 *         E.g. version 1.0 gives highbyte==1, lowbyte==0
 */
unsigned short CALLBACK MvxSockVersion(void);

/**
 * Description: Show the last error in a message box.
 *
 * Argument: struct pointer
 *           Pointer to additional error text.
 * Returns:
 *
 * Remark:
 *
 */
void CALLBACK MvxSockShowLastError( PSERVER_ID pstruct, char *ErrText);

/**
 * Description: Returns the last error in given buffer.
 *
 * Argument: struct pointer
 *           Pointer to buffer or NULL.
 *           Size of the buffer in where to store error text.
 *
 * Returns:  Pointer to buffer if not NULL.
 *           If buffer is NULL, a pointer to internal storage is returned.
 *
 * Remark: Always returns text in ANSI/ASCII format.
 *
 */
char * CALLBACK MvxSockGetLastError( PSERVER_ID pstruct, char *buffer, int buffsize);

/**
 * Description: Retrieve message ID from the last NOK error.
 *
 * Argument: struct pointer
 *           Pointer to buffer or NULL.
 *           Size of the buffer in where to store text.
 *
 * Returns:  Pointer to buffer if not NULL.
 *           If buffer is NULL, a pointer to internal storage is returned.
 *
 * Remark: Always returns text in ANSI/ASCII format.
 *
 */
char * CALLBACK MvxSockGetLastMessageID( PSERVER_ID pstruct, char *buffer, int buffsize);

/**
 * Description: Retrieve name of the input field containing erroneous data
 *              as returned from the last NOK error.
 *
 * Argument: struct pointer
 *           Pointer to buffer or NULL.
 *           Size of the buffer in where to store text.
 *
 * Returns:  Pointer to buffer if not NULL.
 *           If buffer is NULL, a pointer to internal storage is returned.
 *
 * Remark: Always returns text in ANSI/ASCII format.
 *
 */
char * CALLBACK MvxSockGetLastBadField( PSERVER_ID pstruct, char *buffer, int buffsize);

/**
 * Close the conversation
 */
unsigned long CALLBACK MvxSockClose( PSERVER_ID pstruct);

/* This one is not really supported. */
unsigned long CALLBACK MvxSockChgPwd( PSERVER_ID pstruct, char *user, char *oldpwd, char *newpwd);

/**
 * Description: Function to build and execute a transaction built up from field
 *              name/data pairs.
 *
 * Argument: Pointer to struct
 *           Name of transaction to execute
 *
 * Returns:    0 = OK, 0 > Error. 8 is often recoverable, the others are not.
 *
 * Remark: When called with only the struct pointer and NULL for trans name as arguments
 *         the function retrieves the next record in a Lst (multiple) transaction.
 *         The function allocates and maintain it's own memory buffers. To avoid memory
 *         leakage MvxSockClose() shall always be called to close the communication.
 */
unsigned long CALLBACK MvxSockAccess( PSERVER_ID pstruct, char *trans);

/**
 * Description: Clear fields set with MvxSockSetField
 *
 * Argument: Pointer to struct
 *
 * Returns:
 *
 * Remark: Used eg. in pooling functionality. If set fields are not to be used.
 *
 */
void MvxSockClearFields(PSERVER_ID pstruct);

/**
 * Description: Get the data for a specific field.
 *
 * Argument: Pointer to struct
 *           Name of the field to return data from.
 *
 * Returns:  Pointer to an internal buffer containing data from the field.
 *           Data is null terminated and trailing blanks removed.
 *
 * Remark: This function does only work in conjunction with MvxSockAccess().
 *
 */
char * CALLBACK MvxSockGetField(PSERVER_ID pstruct, char *pszFldName);

/**
 * Description: Get the data for a specific field.
 *
 * Argument: Pointer to struct
 *           Name of the field to return data from.
 *
 * Returns:  Pointer to an internal buffer containing Unicode data from the field.
 *           Data is null terminated and trailing blanks removed.
 *
 * Remark: This function does only work in conjunction with MvxSockAccess().
 *
 */
wchar_u * CALLBACK MvxSockGetFieldW(PSERVER_ID pstruct, char *pszFldName);

/**
 * Description: Set the data for a specific field, preparing to call MvxSockAccess.
 *
 * Argument: Pointer to struct
 *           Name of the field to return data from.
 *           Data for the named field.
 *
 * Returns:  Nothing
 *
 * Remark: This function does only work in conjunction with MvxSockAccess().
 *
 */
void CALLBACK MvxSockSetField(PSERVER_ID pstruct, char *pszFldName, char *pszData);

/**
 * Description: Set the data for a specific field, preparing to call MvxSockAccess.
 *
 * Argument: Pointer to struct
 *           Name of the field to return data from.
 *           Data for the named field in Unicode UCS2 encoding.
 *
 * Returns:  Nothing
 *
 * Remark: This function does only work in conjunction with MvxSockAccess().
 *
 */
void CALLBACK MvxSockSetFieldW(PSERVER_ID pstruct, char *pszFldName, wchar_u *pszData);

/**
 * Description: Returns TRUE if there is more data to retrieve using MvxSockGetField()
 *
 * Argument: Pointer to struct
 *
 * Returns:  TRUE = more data to retreive, FALSE = no more data
 *
 * Remark: To be used in loops for "Lst" transactions
 *
 */
unsigned long CALLBACK MvxSockMore(PSERVER_ID pstruct);



/**
 * Description: Function to, from an AS400 client, enable communication towards Movex Java
 *
 * Argument: Pointer to struct
 *
 * Returns:  nothing
 *
 * Remark: This one is only available, and only needed, in an AS400 client running against
 *         Movex Java that communicates with UCS2.
 */
void CALLBACK AS400ToMovexJava( PSERVER_ID pstruct);

/**
 * Description: Set Receive timeout. Max time to wait before receiving answer from Movex.
 *
 * Argument: Pointer to struct.
 *           Time to wait in milli seconds.
 *
 * Returns:  0 if OK, 7 otherwise.
 *
 * Remark: In Windows requires Winsock 2.0.
 *         Read plain text message for details.
 *         Primarily for use with Movex Java where no server side timeout exist.
 *
 */
unsigned long CALLBACK MvxSockSetMaxWait( PSERVER_ID pstruct, int milli);

/**
 * Description: Sends a binary large object to the server.
 *
 * Argument: Pointer to a buffer containing the blob, size of the blob.
 *
 * Returns: 0 if ok, 7 or 8 otherwise. Read plain text in Buff struct member.
 *
 * Remark: This function must be called and the blob thus sent prior to sending the application
 *         unique transaction that completes the process of setting a blob.
 *
 */
unsigned long CALLBACK MvxSockSetBlob( PSERVER_ID pstruct, unsigned char *pByte, unsigned int size);

/**
 * Description: Retrieve a binary large object from the application server.
 *
 * Argument: Pointer to a byte buffer, pointer to a long receiving the size of blob.
 *
 * Returns: 0 if ok, 7 or 8 otherwise. Read plain text in Buff struct member.
 *
 * Remark: This function is to be called in two steps. The first time with a null pointer to
 *         buffer but with pointer to size storage. The client use this size indicator to allocate
 *         a memory buffer with enough size to contain the compete blob and then calls the function again.
 *         This function is to be called after an application unique transaction
 *         that, on the server side, picks up the blob and makes it available for retrieval with
 *         this function.
 *
 */
unsigned long CALLBACK MvxSockGetBlob( PSERVER_ID pstruct, unsigned char *pByte, unsigned int *size);

/**
 * Description: Turn on or off compressed transactions.
 *
 * Argument: Pointer to struct, boolean, TRUE = ON, FALSE = OFF.
 *
 * Returns: 0 if ok, 7 otherwise. Read plain text in Buff struct member.
 *
 * Remark:
 *
 */
#ifdef WIN32
   unsigned long CALLBACK MvxSockSetZippedTransactions( PSERVER_ID pstruct, int mode);
#endif

#ifdef __cplusplus
}
#endif


