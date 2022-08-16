package com.hardbackcollector.sshclient.channels.sftp;

final class SftpConstants {

    /**
     * Initial packet the client sends to the server.
     * <p>
     * uint32 version
     * [extension data]
     * <p>
     * The extension data may be empty, or may be a sequence of
     * string extension_name
     * string extension_data
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-4">
     * Protocol Initialization</a>
     */
    static final byte SSH_FXP_INIT = 1;

    /**
     * Response to the SSH_FXP_INIT packet.
     * <p>
     * uint32 version
     * [extension data]
     * <p>
     * The extension data may be empty, or may be a sequence of
     * string extension_name
     * string extension_data
     */
    static final byte SSH_FXP_VERSION = 2;

    /**
     * Files are opened and created using the SSH_FXP_OPEN message, whose
     * data part is as follows:
     * <p>
     * uint32        id
     * string        filename
     * uint32        pflags
     * ATTRS         attrs
     * <p>
     * The `id' field is the request identifier as for all requests.
     * The `filename' field specifies the file name.
     * The `pflags' field is a bitmask: see {@link #SSH_FXF_READ} etc...
     * The `attrs' field specifies the initial attributes for the file.
     * Default values will be used for those attributes that are not
     * specified.
     */
    static final byte SSH_FXP_OPEN = 3;

    /**
     * A file is closed by using the SSH_FXP_CLOSE request.  Its data field
     * has the following format:
     * <p>
     * uint32     id
     * string     handle
     * <p>
     * where `id' is the request identifier, and `handle' is a handle
     * previously returned in the response to SSH_FXP_OPEN or
     * SSH_FXP_OPENDIR.  The handle becomes invalid immediately after this
     * request has been sent.
     * <p>
     * The response to this request will be a SSH_FXP_STATUS message.  One
     * should note that on some server platforms even a close can fail.
     * This can happen e.g.  if the server operating system caches writes,
     * and an error occurs while flushing cached writes during the close.
     */
    static final byte SSH_FXP_CLOSE = 4;

    /**
     * Once a file has been opened, it can be read using the SSH_FXP_READ
     * message, which has the following format:
     * <p>
     * uint32     id
     * string     handle
     * uint64     offset
     * uint32     len
     * <p>
     * where `id' is the request identifier, `handle' is an open file handle
     * returned by SSH_FXP_OPEN, `offset' is the offset (in bytes) relative
     * to the beginning of the file from where to start reading, and `len'
     * is the maximum number of bytes to read.
     * <p>
     * In response to this request, the server will read as many bytes as it
     * can from the file (up to `len'), and return them in a SSH_FXP_DATA
     * message.  If an error occurs or EOF is encountered before reading any
     * data, the server will respond with SSH_FXP_STATUS.  For normal disk
     * files, it is guaranteed that this will read the specified number of
     * bytes, or up to end of file.  For e.g.  device files this may return
     * fewer bytes than requested.
     */
    static final byte SSH_FXP_READ = 5;

    /**
     * Writing to a file is achieved using the SSH_FXP_WRITE message, which
     * has the following format:
     * <p>
     * uint32     id
     * string     handle
     * uint64     offset
     * string     data
     * <p>
     * where `id' is a request identifier, `handle' is a file handle
     * returned by SSH_FXP_OPEN, `offset' is the offset (in bytes) from the
     * beginning of the file where to start writing, and `data' is the data
     * to be written.
     * <p>
     * The write will extend the file if writing beyond the end of the file.
     * It is legal to write way beyond the end of the file; the semantics
     * are to write zeroes from the end of the file to the specified offset
     * and then the data.  On most operating systems, such writes do not
     * allocate disk space but instead leave "holes" in the file.
     * <p>
     * The server responds to a write request with a SSH_FXP_STATUS message.
     */
    static final byte SSH_FXP_WRITE = 6;

    /**
     * SSH_FXP_LSTAT does not follow symbolic links.
     * <p>
     * uint32     request-id
     * string     path
     */
    static final byte SSH_FXP_LSTAT = 7;

    /**
     * SSH_FXP_FSTAT differs from the {@link #SSH_FXP_LSTAT} and {@link #SSH_FXP_STAT}
     * in that it returns status information for an open file (identified by the file handle).
     * <p>
     * uint32     request-id
     * string     handle
     * <p>
     * where `id' is the request identifier and `handle' is a file handle
     * returned by SSH_FXP_OPEN.
     */
    static final byte SSH_FXP_FSTAT = 8;

    /**
     * SSH_FXP_SETSTAT request is of the following format:
     * <p>
     * uint32     request-id
     * string     path
     * ATTRS      attrs
     * <p>
     * where `id' is the request identifier, `path' specifies the file
     * system object (e.g.  file or directory) whose attributes are to be
     * modified, and `attrs' specifies the modifications to be made to its
     * attributes.
     */
    static final byte SSH_FXP_SETSTAT = 9;

    /**
     * SSH_FXP_FSETSTAT request modifies the attributes of a file which
     * is already open.  It has the following format:
     * <p>
     * uint32     request-id
     * string     handle
     * ATTRS      attrs
     * <p>
     * where `id' is the request identifier, `handle' (MUST be returned by
     * SSH_FXP_OPEN) identifies the file whose attributes are to be
     * modified, and `attrs' specifies the modifications to be made to its
     * attributes.
     */
    static final byte SSH_FXP_FSETSTAT = 10;

    /**
     * uint32     request-id
     * string     path
     */
    static final byte SSH_FXP_OPENDIR = 11;

    /**
     * uint32     request-id
     * string     handle   a handle as returned by SSH_FXP_OPENDIR.
     */
    static final byte SSH_FXP_READDIR = 12;

    /**
     * Files can be removed using the SSH_FXP_REMOVE message.  It has the
     * following format:
     * <p>
     * uint32     id
     * string     filename
     * <p>
     * where `id' is the request identifier and `filename' is the name of
     * the file to be removed.
     * This request cannot be used to remove directories.
     * <p>
     * The server will respond to this request with a SSH_FXP_STATUS message.
     */
    static final byte SSH_FXP_REMOVE = 13;

    /**
     * New directories can be created using the SSH_FXP_MKDIR request.  It
     * has the following format:
     * <p>
     * uint32     id
     * string     path
     * ATTRS      attrs
     * <p>
     * where `id' is the request identifier, `path' and `attrs' specifies
     * the modifications to be made to its attributes.
     */
    static final byte SSH_FXP_MKDIR = 14;

    /**
     * Directories can be removed using the SSH_FXP_RMDIR request, which
     * has the following format:
     * <p>
     * uint32     id
     * string     path
     * <p>
     * where `id' is the request identifier, and `path' specifies the
     * directory to be removed.
     */
    static final byte SSH_FXP_RMDIR = 15;

    /**
     * The SSH_FXP_REALPATH request can be used to have the server
     * canonicalize any given path name to an absolute path.  This is useful
     * for converting path names containing ".." components or relative
     * path names without a leading slash into absolute paths.  The format of
     * the request is as follows:
     * <p>
     * uint32     request-id
     * string     path
     * <p>
     * where `id' is the request identifier and `path' specifies the path
     * name to be canonicalized.  The server will respond with a
     * SSH_FXP_NAME packet containing only one name and a dummy attributes
     * value.  The name is the returned packet will be in canonical form.
     * If an error occurs, the server may also respond with SSH_FXP_STATUS.
     */
    static final byte SSH_FXP_REALPATH = 16;

    /**
     * SSH_FXP_STAT follows symbolic links on the server
     * <p>
     * uint32     request-id
     * string     path
     */
    static final byte SSH_FXP_STAT = 17;

    /**
     * Files (and directories) can be renamed using the SSH_FXP_RENAME
     * message.  Its data is as follows:
     * <p>
     * uint32     id
     * string     oldpath
     * string     newpath
     * <p>
     * where `id' is the request identifier, `oldpath' is the name of an
     * existing file or directory, and `newpath' is the new name for the
     * file or directory.  It is an error if there already exists a file
     * with the name specified by newpath.  The server may also fail rename
     * requests in other situations, for example if `oldpath' and `newpath'
     * point to different file systems on the server.
     * <p>
     * The server will respond to this request with a SSH_FXP_STATUS
     * message.
     */
    static final byte SSH_FXP_RENAME = 18;

    /**
     * The SSH_FXP_READLINK request may be used to read the target of a
     * symbolic link.  It would have a data part as follows:
     * <p>
     * uint32     request-id
     * string     path
     * <p>
     * where `id' is the request identifier and `path' specifies the path
     * name of the symlink to be read.
     * <p>
     * The server will respond with a SSH_FXP_NAME packet containing only
     * one name and a dummy attributes value.  The name in the returned
     * packet contains the target of the link.  If an error occurs, the
     * server may respond with SSH_FXP_STATUS.
     */
    static final byte SSH_FXP_READLINK = 19;

    /**
     * SSH_FXP_SYMLINK request will create a symbolic link on the
     * server.  It is of the following format
     * <p>
     * uint32     request-id
     * string     linkpath
     * string     targetpath
     * <p>
     * where `id' is the request identifier, `linkpath' specifies the path
     * name of the symlink to be created and `targetpath' specifies the
     * target of the symlink.
     * <p>
     * <strong>HOWEVER:</strong>
     *
     * 4. SFTP protocol changes
     * <p>
     * 4.1. sftp: Reversal of arguments to SSH_FXP_SYMLINK
     * <p>
     * When OpenSSH's sftp-server was implemented, the order of the arguments
     * to the SSH_FXP_SYMLINK method was inadvertently reversed. Unfortunately,
     * the reversal was not noticed until the server was widely deployed. Since
     * fixing this to follow the specification would cause incompatibility, the
     * current order was retained. For correct operation, clients should send
     * SSH_FXP_SYMLINK as follows:
     * <p>
     * uint32		id
     * string		targetpath
     * string		linkpath
     *
     * @see com.hardbackcollector.sshclient.ChannelSftp#ln(String, String, boolean)
     * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD">
     * * OpenSSH protocol deviations.</a>
     */
    static final byte SSH_FXP_SYMLINK = 20;

    /**
     * byte     SSH_FXP_STATUS
     * uint32   request-id
     * uint32   error/status code
     * string   error message (ISO-10646 UTF-8 [RFC-2279])
     * string   language tag (as defined in [RFC-1766])
     * error-specific data
     */
    static final byte SSH_FXP_STATUS = 101;

    /**
     * byte       SSH_FXP_HANDLE
     * uint32     request-id
     * string     handle
     */
    static final byte SSH_FXP_HANDLE = 102;

    /**
     * byte       SSH_FXP_DATA
     * uint32     request-id
     * string     data
     * bool       end-of-file [optional]    Sftp v6 field! Some v3 servers do return it
     */
    static final byte SSH_FXP_DATA = 103;

    /**
     * byte       SSH_FXP_NAME
     * uint32     request-id
     * uint32     count
     * repeats count times:
     * string     filename
     * string     longname
     * ATTRS      attrs
     */
    static final byte SSH_FXP_NAME = 104;

    /**
     * byte       SSH_FXP_ATTRS
     * uint32     request-id
     * ATTRS      attrs
     */
    static final byte SSH_FXP_ATTRS = 105;

    /**
     * The SSH_FXP_EXTENDED request provides a generic extension mechanism
     * for adding vendor-specific commands.  The request has the following
     * format:
     * <p>
     * uint32     id
     * string     extended-request
     * ... any request-specific data ...
     * <p>
     * where `id' is the request identifier, and `extended-request' is a
     * string of the format "name@domain", where domain is an internet
     * domain name of the vendor defining the request.  The rest of the
     * request is completely vendor-specific, and servers should only
     * attempt to interpret it if they recognize the `extended-request'
     * name.
     */
    static final byte SSH_FXP_EXTENDED = (byte) 200;

    /**
     * The server may respond to such requests using any of the response
     * packets defined in Section ``Responses from the Server to the
     * Client''.  Additionally, the server may also respond with a
     * SSH_FXP_EXTENDED_REPLY packet, as defined below.  If the server does
     * not recognize the `extended-request' name, then the server MUST
     * respond with SSH_FXP_STATUS with error/status set to
     * SSH_FX_OP_UNSUPPORTED.
     * <p>
     * The SSH_FXP_EXTENDED_REPLY packet can be used to carry arbitrary
     * extension-specific data from the server to the client.  It is of the
     * following format:
     * <p>
     * uint32     id
     * ... any request-specific data ...
     */
    static final byte SSH_FXP_EXTENDED_REPLY = (byte) 201;


    /**
     * SSH_FXP_STATUS: SSH_FX_OK
     * Indicates successful completion of the operation.
     */
    static final int SSH_FX_OK = 0;

    /**
     * SSH_FXP_STATUS: SSH_FX_EOF
     * indicates end-of-file condition; for SSH_FX_READ it means that no
     * more data is available in the file, and for SSH_FX_READDIR it
     * indicates that no more files are contained in the directory.
     */
    static final int SSH_FX_EOF = 1;

    /**
     * SSH_FXP_STATUS: SSH_FX_NO_SUCH_FILE
     * is returned when a reference is made to a file which should exist but doesn't.
     */
    static final int SSH_FX_NO_SUCH_FILE = 2;

    /**
     * SSH_FXP_STATUS: SSH_FX_PERMISSION_DENIED
     * is returned when the authenticated user does not have sufficient
     * permissions to perform the operation.
     */
    static final int SSH_FX_PERMISSION_DENIED = 3;

    /**
     * SSH_FXP_STATUS: SSH_FX_FAILURE
     * is a generic catch-all error message; it should be returned if an
     * error occurs for which there is no more specific error code defined.
     */
    static final int SSH_FX_FAILURE = 4;

    /**
     * SSH_FXP_STATUS: SSH_FX_BAD_MESSAGE
     * may be returned if a badly formatted packet or protocol incompatibility is detected.
     */
    static final int SSH_FX_BAD_MESSAGE = 5;

    /**
     * SSH_FXP_STATUS: SSH_FX_NO_CONNECTION
     * is a pseudo-error which indicates that the client has no
     * connection to the server (it can only be generated locally by the
     * client, and MUST NOT be returned by servers).
     */
    static final int SSH_FX_NO_CONNECTION = 6;

    /**
     * SSH_FXP_STATUS: SSH_FX_CONNECTION_LOST
     * is a pseudo-error which indicates that the connection to the
     * server has been lost (it can only be generated locally by the
     * client, and MUST NOT be returned by servers).
     */
    static final int SSH_FX_CONNECTION_LOST = 7;

    /**
     * SSH_FXP_STATUS: SSH_FX_OP_UNSUPPORTED
     * indicates that an attempt was made to perform an operation which
     * is not supported for the server (it may be generated locally by
     * the client if e.g.  the version number exchange indicates that a
     * required feature is not supported by the server, or it may be
     * returned by the server if the server does not implement an operation).
     */
    static final int SSH_FX_OP_UNSUPPORTED = 8;


    /**
     * pflags
     */
    static final int SSH_FXF_READ = 0x00000001;
    static final int SSH_FXF_WRITE = 0x00000002;
    static final int SSH_FXF_APPEND = 0x00000004;
    static final int SSH_FXF_CREAT = 0x00000008;
    static final int SSH_FXF_EXCL = 0x00000020;
    static final int SSH_FXF_TRUNC = 0x00000010;

    private SftpConstants() {
    }
}
