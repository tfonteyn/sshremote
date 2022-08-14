package com.hardbackcollector.sshclient.channels.sftp;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.ChannelSftp;
import com.hardbackcollector.sshclient.ChannelSubsystem;
import com.hardbackcollector.sshclient.Logger;
import com.hardbackcollector.sshclient.channels.SshChannelException;
import com.hardbackcollector.sshclient.channels.io.MyPipedInputStream;
import com.hardbackcollector.sshclient.channels.session.ChannelSessionImpl;
import com.hardbackcollector.sshclient.transport.Packet;
import com.hardbackcollector.sshclient.transport.SessionImpl;
import com.hardbackcollector.sshclient.utils.Globber;
import com.hardbackcollector.sshclient.utils.SshConstants;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

/**
 * A Channel connected to an sftp server (as a subsystem of the ssh server).
 * <p>
 * This class supports the client side of the sftp protocol,
 * version 3, and implements an interface similar to the
 * usual {@code sftp} command line client.
 *
 * <h3 id="current-directory">Current directory</h3>
 * <p>
 * This sftp client has the concept of a <em>current local directory</em>
 * and a <em>current remote directory</em>. These are not inherent to
 * the protocol, but are used implicitly for all path-based
 * commands sent to the server (for the remote directory) or
 * accessing the local file system (for the local directory).
 * <p>
 * They can be queried by {@link #lpwd} and {@link #pwd}, and
 * changed by {@link #cd cd(dir)} and {@link #lcd lcd(dir)}.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.5">
 * RFC SSH 4254 Connection Protocol, section 6.5. Starting a Shell or a Command</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02">
 * Internet Draft "SSH File Transfer Protocol" (version 02 describing
 * version 3 of the protocol)</a>
 * @see <a href="https://www.sftp.net/specification">SFTP drafts and extensions</a>
 */
public class ChannelSftpImpl
        // Note we're NOT extending ChannelSubsystem as might be expected.
        // Sftp is a tad to complex...
        extends ChannelSessionImpl
        implements ChannelSftp {

    private static final String EXT_POSIX_RENAME_OPENSSH_COM = "posix-rename@openssh.com";
    private static final String EXT_HARDLINK_OPENSSH_COM = "hardlink@openssh.com";
    private static final String EXT_STATVFS_OPENSSH_COM = "statvfs@openssh.com";
    private static final String EXT_FSTATVFS_OPENSSH_COM = "fstatvfs@openssh.com";
    private static final String EXT_FSYNC_OPENSSH_COM = "fsync@openssh.com";

    private static final int DEFAULT_REQUEST_QUEUE_SIZE = 16;

    private static final String ERROR_NO_SUCH_DIRECTORY =
            "No such directory";
    private static final String ERROR_MULTIPLE_FILES =
            "Copying multiple files, but the destination is missing or is a file.";
    private static final String ERROR_CANNOT_RESUME_s =
            "Size mismatch. Cannot resume ";
    private static final String ERROR_s_IS_A_DIRECTORY = " is a directory";


    private static final int CLIENT_VERSION = 3;

    /* 1kb */
    private static final int COPY_BUFFER_SIZE = 0x400;

    /**
     * See {@link #sendWRITE(byte[], long, byte[], int, int)}.
     * <p>
     * 1: FXP byte
     * 4: seq
     * 4 + handle.length
     * 8: offset
     * 4 + dataLength
     * => 21 + handle.length is the fixed space,
     */
    private static final int WRITE_PACKET_HEADER_LEN =
            Packet.HEADER_LEN + CHANNEL_PACKET_HEADER_LEN + 21;

    /** Keep a map to allow users to query for extensions. */
    @Nullable
    private HashMap<String, String> extensions;
    private int server_version = 3;
    private boolean extPosixRename;
    private boolean exHardlink;
    private boolean extStatvfs;
    private boolean extFstatvfs;
    private boolean extFsync;

    /** remote home directory. */
    private String home;
    /** remote current working directory. */
    private String cwd;
    /** local current working directory. */
    private String lcwd;

    @NonNull
    private Charset fileNameEncoding = StandardCharsets.UTF_8;

    @NonNull
    private RequestQueue requestQueue = new RequestQueue(DEFAULT_REQUEST_QUEUE_SIZE);

    /** Package sequence counter. */
    private int seq = 1;

    @Nullable
    private MyPipedInputStream mpIn;

    /** Created when needed; then re-used until the channel is destroyed. */
    @Nullable
    private Packet uploadPacket;

    public ChannelSftpImpl(@NonNull final SessionImpl session) {
        super(session);
    }

    /**
     * Sets the encoding used to convert file names from Strings to bytes.
     * This should be the the same encoding actually used on the server.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.2">
     * SFTP v3 has no specific rule on filename encoding</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-04#section-6.2">
     * SFTP v4 enforces all file names to be UTF-8</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-05#section-6.2">
     * SFTP v5 enforces all file names to be UTF-8</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13#section-6">
     * SFTP v6 extensions to deal with encoding</a>
     */
    public void setFilenameEncoding(@NonNull final String encoding)
            throws UnsupportedEncodingException {
        try {
            fileNameEncoding = Charset.forName(encoding);
        } catch (final IllegalArgumentException e) {
            throw new UnsupportedEncodingException(encoding);
        }
    }

    /**
     * Get the amount of requests which may be sent at any one time.
     *
     * @return how many requests may be sent at any one time.
     */
    public int getBulkRequests() {
        return requestQueue.size();
    }

    /**
     * Specify how many requests may be sent at any one time.
     * Increasing this value may slightly improve file transfer speed but will
     * increase memory usage.  The default is 16 requests.
     *
     * @param maxRequests how many requests may be outstanding at any one time.
     */
    public void setBulkRequests(final int maxRequests) {
        if (maxRequests > 0) {
            requestQueue = new RequestQueue(maxRequests);
        } else {
            requestQueue = new RequestQueue(DEFAULT_REQUEST_QUEUE_SIZE);
        }
    }

    @Override
    protected void onAfterConnect(@NonNull final SessionImpl session)
            throws GeneralSecurityException, IOException, SshChannelException {

        final PipedOutputStream pos = new PipedOutputStream();
        setOutputStream(pos);

        mpIn = new MyPipedInputStream(pos, requestQueue.size() * remoteMaxPacketSize);
        setInputStream(mpIn);

        // byte      SSH_MSG_CHANNEL_REQUEST
        // uint32    recipient channel
        // string    "subsystem"
        // boolean   want reply
        // string    subsystem name
        sendRequest((recipient, x) -> new Packet(SshConstants.SSH_MSG_CHANNEL_REQUEST)
                            .putInt(recipient)
                            .putString(ChannelSubsystem.NAME)
                            .putBoolean(true)
                            .putString(ChannelSftp.NAME),
                    true);

        // Protocol Initialization
        // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-4
        final Packet initPacket = createFxpPacket(SftpConstants.SSH_FXP_INIT)
                .putInt(CLIENT_VERSION);
        sendFxpPacket(initPacket);

        // receive SSH_FXP_VERSION
        final FxpVersionPacket receivedPacket = new FxpVersionPacket(remoteMaxPacketSize);
        receivedPacket.decode(mpIn);

        server_version = receivedPacket.getVersion();
        extensions = receivedPacket.getExtensions();

        // http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD
        extPosixRename = "1".equals(extensions.get(EXT_POSIX_RENAME_OPENSSH_COM));
        exHardlink = "1".equals(extensions.get(EXT_HARDLINK_OPENSSH_COM));
        extStatvfs = "2".equals(extensions.get(EXT_STATVFS_OPENSSH_COM));
        extFstatvfs = "2".equals(extensions.get(EXT_FSTATVFS_OPENSSH_COM));
        extFsync = "1".equals(extensions.get(EXT_FSYNC_OPENSSH_COM));

        lcwd = new File(".").getCanonicalPath();
    }

    @Override
    public int getServerVersion()
            throws SftpException {
        if (!isConnected()) {
            throw new SftpException(SftpConstants.SSH_FX_NO_CONNECTION);
        }
        return server_version;
    }

    /**
     * Get the extension data sent by the server
     * corresponding to the given extension name.
     *
     * @return the String value
     */
    @Nullable
    public String getExtension(@NonNull final String key) {
        return extensions == null ? null : extensions.get(key);
    }

    @Override
    @NonNull
    public String version() {
        return String.valueOf(CLIENT_VERSION);
    }

    @Override
    public void lcd(@NonNull final String path)
            throws SftpException {

        String absPath = absoluteLocalPath(path);
        if (new File(absPath).isDirectory()) {
            try {
                absPath = new File(absPath).getCanonicalPath();
            } catch (final Exception ignore) {
            }
            lcwd = absPath;
            return;
        }
        throw new SftpException(SftpConstants.SSH_FX_NO_SUCH_FILE, ERROR_NO_SUCH_DIRECTORY);
    }

    @Override
    @Nullable
    public String lpwd() {
        return lcwd;
    }

    @Override
    public void cd(@NonNull final String path)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            final String absPath = resolveRemotePath(path);

            sendREALPATH(absPath);
            final byte[] _cwd = receiveNAME();
            final String tmpCwd = byte2str(_cwd);

            sendSTAT(_cwd);
            final SftpATTRS attr = receiveATTRS();

            if ((attr.getFlags() & SftpATTRS.SSH_FILEXFER_ATTR_PERMISSIONS) == 0) {
                throw new SftpException(SftpConstants.SSH_FX_FAILURE, "Cannot cd to: " + tmpCwd);
            }
            if (!attr.isDirectory()) {
                throw new SftpException(SftpConstants.SSH_FX_FAILURE, "Not a directory: " + tmpCwd);
            }

            cwd = tmpCwd;

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    @NonNull
    public String pwd()
            throws SftpException {
        if (cwd == null) {
            cwd = getHome();
        }
        return cwd;
    }

    @Override
    @NonNull
    public String getHome()
            throws SftpException {
        if (home == null) {
            try {
                //noinspection ConstantConditions
                mpIn.updateReadSide();

                sendREALPATH("");
                home = byte2str(receiveNAME());

            } catch (final SftpException e) {
                throw e;
            } catch (final Exception e) {
                throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
            }
        }
        return home;
    }

    @Override
    public void mkdir(@NonNull final String path)
            throws IOException, SshChannelException, GeneralSecurityException {

        //noinspection ConstantConditions
        mpIn.updateReadSide();

        sendMKDIR(absoluteRemotePath(path), null);
        checkStatus();
    }

    @Override
    public void rmdir(@NonNull final String path)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            for (final String absPath : globRemotePath(path)) {
                sendRMDIR(absPath);
                checkStatus();
            }
        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    public void rm(@NonNull final String path)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            for (final String absPath : globRemotePath(path)) {
                sendREMOVE(absPath);
                checkStatus();
            }
        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    public void rename(@NonNull final String oldPath,
                       @NonNull final String newPath)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            final String absOldPath = resolveRemotePath(oldPath);
            String absNewPath;

            final List<String> list = globRemotePath(newPath);
            switch (list.size()) {
                case 1: {
                    absNewPath = list.get(0);
                    break;
                }
                case 0: {
                    absNewPath = absoluteRemotePath(newPath);
                    if (Globber.isPattern(absNewPath)) {
                        throw new SftpException(SftpConstants.SSH_FX_FAILURE,
                                                "Path has wildcards: " + absNewPath);
                    }
                    absNewPath = Globber.unquote(absNewPath);
                    break;
                }
                default:
                    throw new SftpException(SftpConstants.SSH_FX_FAILURE, list.toString());
            }

            sendRENAME(absOldPath, absNewPath);
            checkStatus();

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @NonNull
    public List<LsEntry> ls(@NonNull final String pattern)
            throws SftpException {

        final List<LsEntry> entries = new ArrayList<>();
        final LsEntry.Selector selector = entry -> {
            entries.add(entry);
            return LsEntry.Selector.CONTINUE;
        };

        ls(pattern, selector);
        return entries;
    }

    /**
     * List files specified by the remote {@code path}.
     * <p>
     * Each file and directory will be passed to the
     * {@code LsEntrySelector#select(LsEntry)} method.
     * If that method returns {@code LsEntrySelector#BREAK}, the ls-operation will be
     * canceled immediately.
     * <p>
     * A simple 'get all' selector:
     * <pre>
     *     final List<LsEntry> entries = new ArrayList<>();
     *     final LsEntrySelector selector = entry -> {
     *             entries.add(entry);
     *             return LsEntrySelector.CONTINUE;
     *     };
     *     ls(path, selector);
     *     // entries will now contain the full list
     * </pre>
     *
     * @param path     a path relative to the
     *                 <a href="#current-directory">current remote directory</a>.
     *                 The path can contain glob pattern wildcards ({@code *} or {@code ?})
     *                 in the last component (i.e. after the last {@code /}).
     * @param selector see above
     *
     * @see LsEntry.Selector
     */
    public void ls(@NonNull final String path,
                   @NonNull final LsEntry.Selector selector)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            final String absPath = absoluteRemotePath(path);

            final int lastFileSepChar = absPath.lastIndexOf('/');
            // split into directory and last part of the name, with (potentially) a pattern
            String dir = Globber
                    .unquote(absPath.substring(0, lastFileSepChar == 0 ? 1 : lastFileSepChar));
            final String filenamePart = absPath.substring(lastFileSepChar + 1);

            final boolean patternHasWildcards = Globber.isPattern(filenamePart);
            final byte[] _pattern;
            if (patternHasWildcards) {
                _pattern = filenamePart.getBytes(StandardCharsets.UTF_8);

            } else {
                final String uPath = Globber.unquote(absPath);
                sendSTAT(uPath);
                final SftpATTRS attr = receiveATTRS();
                if (attr.isDirectory()) {
                    dir = uPath;
                    _pattern = null;
                } else {
                    // its a file
                    if (StandardCharsets.UTF_8.equals(fileNameEncoding)) {
                        _pattern = Globber.unquote(filenamePart.getBytes(StandardCharsets.UTF_8));
                    } else {
                        _pattern = str2byte(Globber.unquote(filenamePart));
                    }
                }
            }

            // Ask the server to send us the dir listing. 'dir' must NOT have a trailing slash
            sendOPENDIR(dir);
            final byte[] handle = receiveHANDLE();

            final FxpNamePacket receivedPacket = new FxpNamePacket(remoteMaxPacketSize);

            int action = LsEntry.Selector.CONTINUE;
            while (action == LsEntry.Selector.CONTINUE) {

                sendREADDIR(handle);

                receivedPacket.decodeHeader(mpIn);

                int nrOfEntries = receivedPacket.getNrOfEntries();
                if (nrOfEntries <= 0) {
                    break;
                }

                while (nrOfEntries > 0 && action == LsEntry.Selector.CONTINUE) {
                    receivedPacket.fillBuffer(mpIn);

                    // Read one LS entry:
                    //     string     filename
                    //     string     longname
                    //     ATTRS      attrs
                    final byte[] _filename = receivedPacket.readString();

                    // filter the files we want based on the pattern
                    final boolean wanted;
                    if (_pattern == null) {
                        wanted = true;
                    } else if (patternHasWildcards) {
                        wanted = glob(_pattern, _filename);
                    } else {
                        wanted = Arrays.equals(_pattern, _filename);
                    }

                    if (wanted) {
                        final String filename = byte2str(_filename);

                        // Read the remaining fields
                        final byte[] _longname;
                        if (server_version <= 3) {
                            _longname = receivedPacket.readString();
                        } else {
                            // This field no longer exists in v4+
                            _longname = null;
                        }
                        final SftpATTRS attrs = receivedPacket.readATTRS();

                        final String longname;
                        if (_longname == null) {
                            // generate it from the attrs
                            longname = attrs.getAsString() + " " + filename;
                        } else {
                            longname = byte2str(_longname);
                        }
                        action = selector.select(new LsEntry(filename, longname, attrs));
                    }

                    nrOfEntries--;
                }
            }

            sendCLOSE(handle);
            checkStatus();

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    public void ln(@NonNull final String oldPath,
                   @NonNull final String newPath,
                   final boolean softLink)
            throws SftpException {
        if (!softLink && !exHardlink) {
            throw new SftpException(SftpConstants.SSH_FX_OP_UNSUPPORTED,
                                    EXT_HARDLINK_OPENSSH_COM + " not supported");
        }

        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            final String absOldPath = resolveRemotePath(oldPath);
            final String absNewPath = absoluteRemotePath(newPath);

            if (Globber.isPattern(absNewPath)) {
                throw new SftpException(SftpConstants.SSH_FX_FAILURE,
                                        "Path has wildcards: " + absNewPath);
            }

            if (softLink) {
                sendSYMLINK(absOldPath, Globber.unquote(absNewPath));
            } else {
                sendHARDLINK(absOldPath, Globber.unquote(absNewPath));
            }
            checkStatus();

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    @NonNull
    public SftpATTRS stat(@NonNull final String path)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            sendSTAT(resolveRemotePath(path));
            return receiveATTRS();

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    @NonNull
    public SftpATTRS lstat(@NonNull final String path)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            sendLSTAT(resolveRemotePath(path));
            return receiveATTRS();

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    @NonNull
    public SftpStatVFS statVFS(@NonNull final String path)
            throws SftpException {

        if (!extStatvfs) {
            throw new SftpException(SftpConstants.SSH_FX_OP_UNSUPPORTED,
                                    EXT_STATVFS_OPENSSH_COM + " not supported");
        }

        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            sendSTATVFS(resolveRemotePath(path));
            return receiveStatVFS();

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    public void setStat(@NonNull final String path,
                        @NonNull final SftpATTRS attr)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            for (final String absPath : globRemotePath(path)) {
                sendSETSTAT(absPath, attr);
                checkStatus();
            }
        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    public void chgrp(final int gid,
                      @NonNull final String path)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            for (final String absPath : globRemotePath(path)) {
                sendSTAT(absPath);
                final SftpATTRS attr = receiveATTRS();
                attr.setFLAGS(0);
                attr.setUIDGID(attr.getUid(), gid);
                sendSETSTAT(absPath, attr);
                checkStatus();
            }
        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    public void chown(final int uid,
                      @NonNull final String path)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            for (final String absPath : globRemotePath(path)) {
                sendSTAT(absPath);
                final SftpATTRS attr = receiveATTRS();
                attr.setFLAGS(0);
                attr.setUIDGID(uid, attr.getGid());
                sendSETSTAT(absPath, attr);
                checkStatus();
            }
        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    public void chmod(final int permissions,
                      @NonNull final String path)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            for (final String absPath : globRemotePath(path)) {
                sendSTAT(absPath);
                final SftpATTRS attr = receiveATTRS();
                attr.setFLAGS(0);
                attr.setPERMISSIONS(permissions);
                sendSETSTAT(absPath, attr);
                checkStatus();
            }
        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    /**
     * Changes the modification time of one or more remote files.
     *
     * @param modificationTime the new modification time, in seconds from the unix epoch.
     * @param path             a glob pattern of the files to be changed, relative to the
     *                         <a href="#current-directory">current remote directory</a>.
     */
    public void setModificationTime(final int modificationTime,
                                    @NonNull final String path)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            for (final String absPath : globRemotePath(path)) {
                sendSTAT(absPath);
                final SftpATTRS attr = receiveATTRS();
                attr.setFLAGS(0);
                attr.setACMODTIME(attr.getATime(), modificationTime);
                sendSETSTAT(absPath, attr);
                checkStatus();
            }
        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    @NonNull
    public String readlink(@NonNull final String path)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            sendREADLINK(resolveRemotePath(path));
            return byte2str(receiveNAME());

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    @NonNull
    public String realpath(@NonNull final String path)
            throws SftpException {
        try {
            sendREALPATH(absoluteRemotePath(path));
            return byte2str(receiveNAME());

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }


    @Override
    @NonNull
    public InputStream get(@NonNull final String srcPath,
                           @Nullable final SftpProgressMonitor progressListener,
                           final long initialOffset)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            final String srcFilename = resolveRemotePath(srcPath);
            sendSTAT(srcFilename);
            final SftpATTRS srcAttr = receiveATTRS();
            if (srcAttr.isDirectory()) {
                throw new SftpException(SftpConstants.SSH_FX_OP_UNSUPPORTED,
                                        srcFilename + ERROR_s_IS_A_DIRECTORY);
            }

            if (progressListener != null) {
                progressListener.init(SftpProgressMonitor.GET, srcFilename, "", srcAttr.getSize());
            }

            sendOPENR(srcFilename);
            final byte[] handle = receiveHANDLE();

            requestQueue.init();

            return new InputStream() {
                /** The buffer for multi-byte reads. */
                private final FxpBuffer fxpBuffer = new FxpBuffer(remoteMaxPacketSize);
                /**
                 * The amount of bytes we'll ask the server to send in each request.
                 * (Always try to fill the entire packet)
                 */
                private final int requestLen = remoteMaxPacketSize - CHANNEL_PACKET_HEADER_LEN;
                /** Temporary buffer for reading a single byte of data. */
                private final byte[] _bb = new byte[1];

                /** the offset in the remote file from where to read the next blob of data. */
                private long requestOffset = initialOffset;

                private long current_offset = initialOffset;

                private int request_max = 1;

                /** Flag set when close() has been called. */
                private boolean streamClosed;

                private int rest_length;
                private byte[] rest_byte = new byte[COPY_BUFFER_SIZE];


                @Override
                public int read()
                        throws IOException {
                    if (streamClosed) {
                        return -1;
                    }
                    final int i = read(_bb, 0, 1);
                    if (i == -1) {
                        return -1;
                    } else {
                        return _bb[0] & 0xff;
                    }
                }

                @Override
                public int read(@NonNull final byte[] buf)
                        throws IOException {
                    if (streamClosed) {
                        return -1;
                    }
                    return read(buf, 0, buf.length);
                }

                @Override
                public int read(@NonNull final byte[] buf,
                                final int offset,
                                int len)
                        throws IOException {
                    if (streamClosed) {
                        return -1;
                    }

                    Objects.checkFromIndexSize(off, len, b.length);
                    if (len == 0) {
                        return 0;
                    }

                    // read 'len' bytes as required from the cached buffer until exhausted
                    if (rest_length > 0) {
                        final int foo = Math.min(rest_length, len);
                        System.arraycopy(rest_byte, 0, buf, offset, foo);

                        if (foo != rest_length) {
                            System.arraycopy(rest_byte, foo, rest_byte, 0, rest_length - foo);
                        }

                        if (progressListener != null && !progressListener.count(length)) {
                            // we're cancelled
                            close();
                            return -1;
                        }

                        rest_length -= foo;
                        return foo;
                    }

                    // contact the server to get more data
                    if (remoteMaxPacketSize - CHANNEL_PACKET_HEADER_LEN < len) {
                        len = remoteMaxPacketSize - CHANNEL_PACKET_HEADER_LEN;
                    }

                    if (requestQueue.count() == 0
                            || true // working around slow transfer speed for
                        // some sftp servers including Titan FTP.
                    ) {
                        // send as many requests in parallel as we can to speed things up
                        while (requestQueue.count() < request_max) {
                            try {
                                sendREAD(handle, requestOffset, requestLen, requestQueue);
                            } catch (final IOException e) {
                                throw e;
                            } catch (final Exception e) {
                                throw new IOException(e);
                            }
                            requestOffset += requestLen;
                        }
                    }

                    // start reading the next packet
                    fxpBuffer.readHeader(mpIn);
                    rest_length = fxpBuffer.getFxpLength();

                    final QueuedRequest queuedRequest;
                    try {
                        queuedRequest = requestQueue.get(fxpBuffer.getRequestId());
                    } catch (final OutOfOrderException e) {
                        requestOffset = e.offset;
                        // throw away the entire packet
                        //noinspection ResultOfMethodCallIgnored
                        skip(fxpBuffer.getFxpLength());
                        requestQueue.cancel();
                        return 0;

                    } catch (final SftpException e) {
                        throw new IOException(e);
                    }

                    // a status packet is a valid response
                    if (fxpBuffer.getFxpType() == SftpConstants.SSH_FXP_STATUS) {
                        fxpBuffer.readPayload(mpIn);
                        final int status = fxpBuffer.getInt();
                        rest_length = 0;
                        if (status == SftpConstants.SSH_FX_EOF) {
                            close();
                            return -1;
                        }
                        throw new IOException(createStatusException(fxpBuffer, status));
                    }

                    // but if we did not get a status or data packet, we have a problem
                    if (fxpBuffer.getFxpType() != SftpConstants.SSH_FXP_DATA) {
                        final SftpException cause = new SftpException(
                                SftpConstants.SSH_FX_BAD_MESSAGE,
                                "invalid type=" + fxpBuffer.getFxpType());
                        throw new IOException(cause);
                    }

                    // throwing away the header, read the next field from the input stream
                    // for the current SSH_FXP_DATA packet which is the payload length.
                    final int payloadLength = fxpBuffer.readInt(mpIn);
                    rest_length -= 4;

                    /*
                     Since sftp protocol version 6, "end-of-file" has been defined,

                     byte   SSH_FXP_DATA
                     uint32 request-id
                     string data
                     bool   end-of-file [optional]

                     but some sftp server will send such a field in the sftp protocol 3,
                     so check if there are more bytes than expected
                     */
                    final int optional_data = rest_length - payloadLength;

                    current_offset += payloadLength;

                    int foo = payloadLength;
                    if (foo > 0) {
                        int bytesRead = mpIn.read(buf, offset, Math.min(foo, len));
                        if (bytesRead < 0) {
                            // end-of-stream reached
                            return -1;
                        }
                        foo -= bytesRead;
                        rest_length = foo;

                        if (foo > 0) {
                            if (rest_byte.length < foo) {
                                rest_byte = new byte[foo];
                            }
                            int _s = 0;
                            int _len = foo;
                            while (_len > 0) {
                                bytesRead = mpIn.read(rest_byte, _s, _len);
                                if (bytesRead <= 0) {
                                    // end-of-stream reached
                                    break;
                                }
                                _s += bytesRead;
                                _len -= bytesRead;
                            }
                        }

                        if (optional_data > 0) {
                            //noinspection ResultOfMethodCallIgnored
                            mpIn.skip(optional_data);
                        }

                        // Are we expecting more data? If so, request the server for it.
                        if (payloadLength < queuedRequest.length) {
                            requestQueue.cancel();
                            try {
                                sendREAD(handle,
                                         queuedRequest.offset + payloadLength,
                                         (int) (queuedRequest.length - payloadLength),
                                         requestQueue);
                            } catch (final IOException e) {
                                throw e;
                            } catch (final Exception e) {
                                throw new IOException(e);
                            }
                            requestOffset = queuedRequest.offset + queuedRequest.length;
                        }

                        if (request_max < requestQueue.size()) {
                            request_max++;
                        }

                    if (progressListener != null && !progressListener.count(totalBytesRead)) {
                        // we're cancelled
                        close();
                        return -1;
                    }

                        return bytesRead;
                    }
                    return 0;
                }

                @Override
                public void close()
                        throws IOException {
                    if (streamClosed) {
                        return;
                    }
                    streamClosed = true;
                    if (progressListener != null) {
                        progressListener.end();
                    }

                    requestQueue.cancel();
                    try {
                        sendCLOSE(handle);
                        checkStatus();
                    } catch (final IOException e) {
                        throw e;
                    } catch (final Exception e) {
                        throw new IOException(e);
                    }
                }
            };

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    public void get(@NonNull final String srcPath,
                    @NonNull final String dstPath,
                    @Nullable final SftpProgressMonitor monitor,
                    @NonNull final Mode mode)
            throws SftpException {

        File currentDestFile = null;
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            // The destination MUST be a single name (i.e. no wildcards)
            // but MAY be either a file or a directory.
            String absDstPath = absoluteLocalPath(dstPath);
            final boolean dstIsDirectory = new File(absDstPath).isDirectory();
            // make sure a directory has the local file separator at the end
            if (dstIsDirectory && !absDstPath.endsWith(File.separator)) {
                absDstPath += File.separator;
            }

            // expand the remote path. We MUST have at least one file to continue.
            final List<String> srcFilenames = globRemotePath(srcPath);
            if (srcFilenames.isEmpty()) {
                throw new SftpException(SftpConstants.SSH_FX_NO_SUCH_FILE, srcPath);
            }
            // If we have multiple files to download the destination MUST be a directory
            if (srcFilenames.size() > 1 && !dstIsDirectory) {
                throw new SftpException(SftpConstants.SSH_FX_FAILURE, ERROR_MULTIPLE_FILES);
            }

            // We now have either:
            // ONE source file, and either a file or dir as destination;
            // one or more source files, and a DIR as destination.

            for (final String absSrcPath : srcFilenames) {
                sendSTAT(absSrcPath);
                final SftpATTRS srcAttr = receiveATTRS();
                if (srcAttr.isDirectory()) {
                    throw new SftpException(SftpConstants.SSH_FX_OP_UNSUPPORTED,
                                            absSrcPath + ERROR_s_IS_A_DIRECTORY);
                }

                final String dstFilename;
                // If the destination is a directory, create a fully qualified
                // filename by combining remote directory + source (local) filename
                if (dstIsDirectory) {
                    // absDstPath already has a File.separator at the end
                    final StringBuilder sb = new StringBuilder(absDstPath);
                    // grab the last part of the source path, i.e. the filename
                    final int i = absSrcPath.lastIndexOf('/');
                    if (i == -1) {
                        sb.append(absSrcPath);
                    } else {
                        sb.append(absSrcPath.substring(i + 1));
                    }

                    dstFilename = sb.toString();

                    //TODO: this logic is flawed... revise
                    if (dstFilename.contains("..")) {
                        final String orig = new File(absDstPath).getCanonicalPath();
                        final String resolved = new File(dstFilename).getCanonicalPath();

                        if (resolved.length() <= orig.length()
                                || !resolved.substring(0, orig.length() + 1)
                                            .equals(orig + File.separator)) {
                            throw new SftpException(SftpConstants.SSH_FX_FAILURE,
                                                    "Attempt to write to an unexpected filename: "
                                                            + dstFilename);
                        }
                    }
                } else {
                    // It's already a fully qualified filename
                    dstFilename = absDstPath;
                }

                currentDestFile = new File(dstFilename);

                long dstFileSize = 0;
                if (mode == Mode.Resume) {
                    dstFileSize = currentDestFile.length();

                    final long srcFileSize = srcAttr.getSize();
                    if (dstFileSize > srcFileSize) {
                        throw new SftpException(SftpConstants.SSH_FX_FAILURE,
                                                ERROR_CANNOT_RESUME_s + absSrcPath);

                    } else if (dstFileSize == srcFileSize) {
                        // This file is already complete
                        continue;
                    }
                }

                if (monitor != null) {
                    monitor.init(SftpProgressMonitor.GET, absSrcPath, dstFilename,
                                 srcAttr.getSize());
                    if (mode == Mode.Resume) {
                        monitor.count(dstFileSize);
                    }
                }

                try (final OutputStream fos =
                             new FileOutputStream(currentDestFile, mode != Mode.Overwrite)) {
                    _get(absSrcPath, fos, monitor, mode, dstFileSize);
                }
                // reset when done (see catch clause below)
                currentDestFile = null;
            }

        } catch (final SftpException e) {
            cleanupZeroByteFiles(currentDestFile);
            throw e;

        } catch (final Exception e) {
            cleanupZeroByteFiles(currentDestFile);

            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    public void get(@NonNull final String srcPath,
                    @NonNull final OutputStream dstStream,
                    @Nullable final SftpProgressMonitor monitor,
                    @NonNull final Mode mode,
                    final long skip)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            final String srcFilename = resolveRemotePath(srcPath);
            sendSTAT(srcFilename);
            final SftpATTRS srcAttr = receiveATTRS();
            if (srcAttr.isDirectory()) {
                throw new SftpException(SftpConstants.SSH_FX_OP_UNSUPPORTED,
                                        srcFilename + ERROR_s_IS_A_DIRECTORY);
            }

            if (mode == Mode.Resume) {
                final long srcSize = srcAttr.getSize();
                if (skip > srcSize) {
                    throw new SftpException(SftpConstants.SSH_FX_FAILURE,
                                            ERROR_CANNOT_RESUME_s + srcFilename);

                } else if (skip == srcSize) {
                    // This file is already complete
                    return;
                }
            }

            if (monitor != null) {
                monitor.init(SftpProgressMonitor.GET, srcFilename, "", srcAttr.getSize());

                if (mode == Mode.Resume) {
                    monitor.count(skip);
                }
            }

            _get(srcFilename, dstStream, monitor, mode, skip);

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    /**
     * Downloads an <strong>absolute path (filename)</strong> to an OutputStream.
     * The path MUST be valid and checked before.
     *
     * @param srcFilename the fully qualified remote source file name
     * @param dstStream   the destination output stream.
     * @param monitor     (optional) progress listener
     * @param mode        the transfer {@link Mode}
     * @param skip        only used If the {@code mode} == {@code Mode#Resume} :
     *                    the position in the remote file where we should start the download
     */
    private void _get(@NonNull final String srcFilename,
                      @NonNull final OutputStream dstStream,
                      @Nullable final SftpProgressMonitor monitor,
                      @NonNull final Mode mode,
                      final long skip)
            throws SftpException, IOException {
        try {
            // single, fully qualified filename
            sendOPENR(srcFilename);
            final byte[] handle = receiveHANDLE();

            long offset = 0;
            if (mode == Mode.Resume) {
                offset = skip;
            }

            int request_max = 1;
            requestQueue.init();

            // the offset in the remote file from where to read the next blob of data.
            long requestOffset = offset;

            // The amount of bytes we'll ask the server to send in each request.
            // (Always try to fill the entire packet)
            final int requestLen = remoteMaxPacketSize - CHANNEL_PACKET_HEADER_LEN;

            final FxpBuffer fxpBuffer = new FxpBuffer(remoteMaxPacketSize);

            loop:
            while (true) {

                // send as many requests in parallel as we can to speed things up
                while (requestQueue.count() < request_max) {
                    sendREAD(handle, requestOffset, requestLen, requestQueue);
                    requestOffset += requestLen;
                }

                //noinspection ConstantConditions
                fxpBuffer.readHeader(mpIn);

                final QueuedRequest queuedRequest;
                try {
                    queuedRequest = requestQueue.get(fxpBuffer.getRequestId());
                } catch (final OutOfOrderException e) {
                    requestOffset = e.offset;
                    skip(fxpBuffer.getFxpLength());
                    requestQueue.cancel();
                    continue;
                }

                // a status packet is a valid response
                if (fxpBuffer.getFxpType() == SftpConstants.SSH_FXP_STATUS) {
                    fxpBuffer.readPayload(mpIn);
                    final int status = fxpBuffer.getInt();
                    if (status == SftpConstants.SSH_FX_EOF) {
                        break;
                    }
                    throw createStatusException(fxpBuffer, status);
                }

                // but if we did not get a status or data packet, we have a problem
                if (fxpBuffer.getFxpType() != SftpConstants.SSH_FXP_DATA) {
                    break;
                }

                // the total length of data we can read from the input stream
                // for the current SSH_FXP_DATA packet
                int length = fxpBuffer.getFxpLength();

                // throwing away the header, read the next field from the input stream
                // for the current SSH_FXP_DATA packet which is the payload length.
                final int payloadLength = fxpBuffer.readInt(mpIn);
                length -= 4;

                // Do we have any extra data ? (i.e. "end-of-file" field, see SSH_FXP_DATA docs).
                // Not all servers send this.
                final int optionalDataLen = length - payloadLength;

                int bytesStillToRead = payloadLength;
                while (bytesStillToRead > 0) {
                    final int bytesRead = mpIn.read(fxpBuffer.data, 0,
                                                    Math.min(bytesStillToRead,
                                                             fxpBuffer.data.length));
                    if (bytesRead < 0) {
                        // end-of-stream reached
                        break loop;
                    }
                    // stream it forward to the user defined output stream
                    dstStream.write(fxpBuffer.data, 0, bytesRead);

                    offset += bytesRead;
                    bytesStillToRead -= bytesRead;

                    if (monitor != null && !monitor.count(bytesRead)) {
                        // user (process) cancelled us. Remove all expected remaining data.
                        skip(bytesStillToRead);
                        if (optionalDataLen > 0) {
                            skip(optionalDataLen);
                        }
                        // and abandon the entire download
                        break loop;
                    }
                }
                // we read all we could, now skip the extra/unexpected data if there was any
                if (optionalDataLen > 0) {
                    skip(optionalDataLen);
                }

                // Are we expecting more data? If so, request the server for it.
                if (payloadLength < queuedRequest.length) {
                    requestQueue.cancel();
                    sendREAD(handle,
                             queuedRequest.offset + payloadLength,
                             (int) (queuedRequest.length - payloadLength),
                             requestQueue);
                    requestOffset = queuedRequest.offset + queuedRequest.length;
                }

                if (request_max < requestQueue.size()) {
                    request_max++;
                }
            }
            dstStream.flush();

            if (monitor != null) {
                monitor.end();
            }

            requestQueue.cancel();

            sendCLOSE(handle);
            checkStatus();

        } catch (final IOException | SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }


    @Override
    @NonNull
    public OutputStream put(@NonNull final String dstPath,
                            @Nullable final SftpProgressMonitor progressListener,
                            @NonNull final Mode mode,
                            final long offset)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            // There is no local filename to use (as its a Stream) so we cannot use
            // that to create the server-side file. We MUST have an actual filename.
            final String dstFilename = resolveRemotePath(dstPath);
            sendSTAT(dstFilename);
            SftpATTRS attr = null;
            try {
                attr = receiveATTRS();
            } catch (final SftpException | IOException ignore) {
                // didn't exist, that's ok.
            }
            // but if it did exist, it should NOT be a directory
            if (attr != null && attr.isDirectory()) {
                throw new SftpException(SftpConstants.SSH_FX_FAILURE,
                                        dstFilename + ERROR_s_IS_A_DIRECTORY);
            }

            // we need a 'final' but still need to be able to write to it...
            final long[] _offset = new long[1];
            _offset[0] = offset;
            // skip to the current end of file if required
            if (mode == Mode.Resume || mode == Mode.Append) {
                if (attr != null) {
                    // add to the offset
                    _offset[0] += attr.getSize();
                }
            }

            if (progressListener != null) {
                progressListener.init(SftpProgressMonitor.PUT, "", dstFilename,
                                      SftpProgressMonitor.UNKNOWN_SIZE);
            }

            if (mode == Mode.Overwrite) {
                sendOPENW(dstFilename);
            } else {
                sendOPENA(dstFilename);
            }
            final byte[] handle = receiveHANDLE();

            return new OutputStream() {
                /** Temporary buffer for writing a single byte of data. */
                private final byte[] _bb = new byte[1];
                private boolean streamClosed;

                private boolean initialized;

                /** the initial sequence counter(id) from the channel when the stream was opened. */
                private int startSeqId;
                /** The amount of packets we send. */
                private int writeCount;
                /** The amount of packets for which we received acknowledgement. */
                private int ackCount;

                @Override
                public void write(final int w)
                        throws IOException {
                    _bb[0] = (byte) w;
                    write(_bb, 0, 1);
                }

                /**
                 * Sends the given data to the server with a {@link SftpConstants#SSH_FXP_WRITE}.
                 */
                @Override
                public void write(@NonNull final byte[] data,
                                  final int offset,
                                  final int length)
                        throws IOException {
                    if (!initialized) {
                        startSeqId = seq;
                        initialized = true;
                    }

                    if (streamClosed) {
                        throw new IOException(ERROR_STREAM_CLOSED);
                    }

                    int bufOffset = offset;
                    int bytesToWrite = length;
                    try {
                        while (bytesToWrite > 0) {
                            final int bytesSend = sendWRITE(handle, _offset[0],
                                                            data, bufOffset, bytesToWrite);
                            writeCount++;
                            _offset[0] += bytesSend;
                            bufOffset += bytesSend;
                            bytesToWrite -= bytesSend;

                            if (seq - 1 == startSeqId || mpIn.available() >= COPY_BUFFER_SIZE) {
                                while (mpIn.available() > 0) {
                                    final int ackId = checkStatus();
                                    if (startSeqId > ackId || ackId > seq - 1) {
                                        if (session.getLogger().isEnabled(Logger.ERROR)) {
                                            session.getLogger().log(Logger.ERROR, () -> "ack error:"
                                                    + " startSeqId=" + startSeqId
                                                    + ", seq=" + seq
                                                    + ", ackId=" + ackId);
                                        }

                                        throw new SftpException(SftpConstants.SSH_FX_BAD_MESSAGE,
                                                                ERROR_SEQUENCE_MISMATCH);
                                    }
                                    ackCount++;
                                }
                            }
                        }

                        if (progressListener != null && !progressListener.count(length)) {
                            close();
                            throw new IOException("canceled by progressListener");
                        }
                    } catch (final IOException e) {
                        throw e;
                    } catch (final Exception e) {
                        throw new IOException(e);
                    }
                }


                @Override
                public void flush()
                        throws IOException {

                    if (streamClosed) {
                        throw new IOException(ERROR_STREAM_CLOSED);
                    }

                    if (initialized) {
                        try {
                            while (writeCount > ackCount) {
                                checkStatus();
                                ackCount++;
                            }
                        } catch (final SftpException e) {
                            throw new IOException(e);
                        }
                    }
                }

                @Override
                public void close()
                        throws IOException {
                    if (streamClosed) {
                        return;
                    }

                    flush();

                    if (progressListener != null) {
                        progressListener.end();
                    }
                    try {
                        sendCLOSE(handle);
                        checkStatus();

                    } catch (final IOException e) {
                        throw e;
                    } catch (final Exception e) {
                        throw new IOException(e);
                    }
                    streamClosed = true;
                }
            };

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    public void put(@NonNull final String srcFilename,
                    @NonNull final String dstPath,
                    @Nullable final SftpProgressMonitor progressListener,
                    @NonNull final Mode mode)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            // The destination MUST be a single name (i.e. no wildcards)
            // but MAY be either a file or a directory.
            String absDstPath = resolveRemotePath(dstPath);
            sendSTAT(absDstPath);

            boolean isDirectory = false;
            try {
                isDirectory = receiveATTRS().isDirectory();
                // make sure a directory has the remote file separator at the end
                if (isDirectory && !absDstPath.endsWith("/")) {
                    absDstPath += '/';
                }
            } catch (final IOException | SftpException ignore) {
                // didn't exist, that's ok.
            }

            // expand the local path. We MUST have at least one file to continue.
            final List<String> srcFilenames = globLocalPath(srcFilename);
            if (srcFilenames.isEmpty()) {
                throw new SftpException(SftpConstants.SSH_FX_NO_SUCH_FILE, srcFilename);
            }
            // If we have multiple files to upload the destination MUST be a directory
            if (srcFilenames.size() > 1 && !isDirectory) {
                throw new SftpException(SftpConstants.SSH_FX_FAILURE, ERROR_MULTIPLE_FILES);
            }

            // We now have either:
            // ONE source file, and either a file or dir as destination;
            // one or more source files, and a DIR as destination.

            for (final String srcPath : srcFilenames) {
                final String dstFilename;
                // If the destination is a directory, create a fully qualified
                // filename by combining remote directory + source (local) filename
                if (isDirectory) {
                    // absDstPath already has a '/'' at the end
                    final StringBuilder sb = new StringBuilder(absDstPath);
                    // grab the last part of the local source path, i.e. the filename
                    final int i = srcPath.lastIndexOf(File.separatorChar);
                    if (i == -1) {
                        sb.append(srcPath);
                    } else {
                        sb.append(srcPath.substring(i + 1));
                    }
                    dstFilename = sb.toString();

                } else {
                    // It's already a fully qualified filename
                    dstFilename = absDstPath;
                }

                long dstFileSize = 0;
                if (mode == Mode.Resume) {
                    try {
                        sendSTAT(dstFilename);
                        final SftpATTRS attr = receiveATTRS();
                        dstFileSize = attr.getSize();
                    } catch (final Exception ignore) {
                        // didn't exist, that's ok.
                    }

                    final long srcFileSize = new File(srcPath).length();
                    if (srcFileSize < dstFileSize) {
                        throw new SftpException(SftpConstants.SSH_FX_FAILURE,
                                                ERROR_CANNOT_RESUME_s + dstFilename);
                    }
                    if (srcFileSize == dstFileSize) {
                        // This file is already complete
                        continue;
                    }
                }

                if (progressListener != null) {
                    progressListener.init(SftpProgressMonitor.PUT,
                                          srcPath, dstFilename,
                                          new File(srcPath).length());
                    if (mode == Mode.Resume) {
                        progressListener.count(dstFileSize);
                    }
                }

                try (final FileInputStream srcStream = new FileInputStream(srcPath)) {
                    _put(srcStream, dstFilename, progressListener, mode);
                }
            }
        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    @Override
    public void put(@NonNull final InputStream srcStream,
                    @NonNull final String dstPath,
                    @Nullable final SftpProgressMonitor progressListener,
                    @NonNull final Mode mode)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            // There is no local filename to use (as its a Stream) so we cannot use
            // that to create the server-side file. We MUST have an actual filename.
            final String dstFilename = resolveRemotePath(dstPath);
            sendSTAT(dstFilename);

            boolean isDirectory = false;
            try {
                isDirectory = receiveATTRS().isDirectory();
            } catch (final IOException | SftpException ignore) {
                // didn't exist, that's ok.
            }
            // but if it did exist, it should NOT be a directory
            if (isDirectory) {
                throw new SftpException(SftpConstants.SSH_FX_FAILURE,
                                        dstFilename + ERROR_s_IS_A_DIRECTORY);
            }

            if (progressListener != null) {
                progressListener.init(SftpProgressMonitor.PUT, "", dstFilename,
                                      SftpProgressMonitor.UNKNOWN_SIZE);
            }

            _put(srcStream, dstFilename, progressListener, mode);

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    /**
     * Not for external use.
     *
     * @param srcStream   the local source we want to upload
     * @param dstFilename fully qualified remote single filename
     * @param monitor     (optional) progress listener
     * @param mode        the transfer {@link Mode}
     */
    private void _put(@NonNull final InputStream srcStream,
                      @NonNull final String dstFilename,
                      @Nullable final SftpProgressMonitor monitor,
                      @NonNull final Mode mode)
            throws SftpException {

        // Create on first use, re-use otherwise; the logic flow relies on that.
        if (uploadPacket == null) {
            uploadPacket = new Packet(localMaxPacketSize);
        }

        // we can send multiple packets in parallel.
        final int bulkRequests = requestQueue.size();

        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            // The offset in the file(stream); updated as we send packets with data to the server
            long offset = 0;

            if (mode == Mode.Resume || mode == Mode.Append) {
                long skip = 0;
                try {
                    sendSTAT(dstFilename);
                    final SftpATTRS attr = receiveATTRS();
                    skip = attr.getSize();
                } catch (final Exception ignore) {
                }

                if (mode == Mode.Resume && skip > 0) {
                    final long skipped = srcStream.skip(skip);
                    if (skipped < skip) {
                        throw new SftpException(SftpConstants.SSH_FX_FAILURE,
                                                ERROR_CANNOT_RESUME_s + dstFilename);
                    }
                }

                offset += skip;
            }

            // open the remote file, and get the file handle.
            if (mode == Mode.Overwrite) {
                sendOPENW(dstFilename);
            } else {
                sendOPENA(dstFilename);
            }
            final byte[] handle = receiveHANDLE();

            // offset where the next set of file data will be written to the packet buffer
            final int dataOffset = WRITE_PACKET_HEADER_LEN + handle.length;
            // the amount of file data we can upload in this packet
            int dataLength = localMaxPacketSize - (dataOffset + Packet.SAFE_MARGIN);

            final int startSeqId = seq;
            int ackCount = 0;

            // initially 'data' just points to the packet data.
            // During reading the file into 'data' we might have to create a larger buffer.
            // When sending, we'll check if we can use the data as-is -> if it's STILL
            // pointing to the packet; or if we need to copy the bytes around.
            byte[] data = uploadPacket.data;

            while (true) {
                // The offset into the data buffer, updated during the read-loop.
                int currentOffset = dataOffset;
                // The number of bytes we'll WANT to read from the stream into the packet
                int bytesToRead = dataLength;
                // number of bytes read in a single read from the stream
                int bytesRead;
                // the sum of 'bytesRead', updated during the read-loop.
                int totalBytes = 0;
                do {
                    bytesRead = srcStream.read(data, currentOffset, bytesToRead);
                    if (bytesRead > 0) {
                        currentOffset += bytesRead;
                        bytesToRead -= bytesRead;
                        totalBytes += bytesRead;
                    }
                }
                while (bytesToRead > 0 && bytesRead > 0);

                if (totalBytes <= 0) {
                    // the input stream was empty, quit.
                    break;
                }

                int bytesToWrite = totalBytes;
                while (bytesToWrite > 0) {
                    // First check and process any incoming acknowledgement packets
                    if (seq - 1 == startSeqId || seq - startSeqId - ackCount >= bulkRequests) {

                        while (seq - startSeqId - ackCount >= bulkRequests) {
                            final int ackId = checkStatus();
                            if (startSeqId > ackId || ackId > seq - 1) {
                                if (session.getLogger().isEnabled(Logger.ERROR)) {
                                    session.getLogger().log(Logger.ERROR, () -> "ack error:"
                                            + " startSeqId=" + startSeqId
                                            + ", seq=" + seq
                                            + ", ackId=" + ackId);
                                }
                                if (ackId != seq) {
                                    throw new SftpException(SftpConstants.SSH_FX_BAD_MESSAGE,
                                                            ERROR_SEQUENCE_MISMATCH);
                                }
                            }
                            ackCount++;
                        }
                    }

                    // send the next batch of file data
                    bytesToWrite -= sendWRITE(handle, offset, data, 0, bytesToWrite);

                    // optimization to avoid copying the array if possible
                    // See #sendWRITE
                    if (!Arrays.equals(data, uploadPacket.data)) {
                        data = uploadPacket.data;
                        dataLength = localMaxPacketSize - (dataOffset + Packet.SAFE_MARGIN);
                    }
                }

                offset += totalBytes;

                if (monitor != null && !monitor.count(totalBytes)) {
                    break;
                }
            }

            final int _ackCount = seq - startSeqId;
            while (_ackCount > ackCount) {
                checkStatus();
                ackCount++;
            }

            if (monitor != null) {
                monitor.end();
            }

            sendCLOSE(handle);
            checkStatus();

        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
    }

    /**
     * If the given file exists but is zero bytes, delete it silently.
     * Any non-zero file is left as-is to allow a resume at a later time.
     *
     * @param currentDestFile to potentially delete
     */
    private void cleanupZeroByteFiles(@Nullable final File currentDestFile) {

        if (currentDestFile != null
                && currentDestFile.exists()
                && currentDestFile.length() == 0) {
            //noinspection ResultOfMethodCallIgnored
            currentDestFile.delete();
        }
    }

    private void sendSTAT(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_STAT, str2byte(path), null);
    }

    private void sendSTAT(@NonNull final byte[] path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_STAT, path, null);
    }

    private void sendLSTAT(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_LSTAT, str2byte(path), null);
    }

    private void sendFSTAT(@NonNull final byte[] handle)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_FSTAT, handle, null);
    }

    private void sendSETSTAT(@NonNull final String path,
                             @NonNull final SftpATTRS attr)
            throws IOException, GeneralSecurityException, SshChannelException {

        final byte[] _path = str2byte(path);

        final Packet packet = createFxpPacket(SftpConstants.SSH_FXP_SETSTAT)
                .putInt(seq++)
                .putString(_path);
        attr.putInto(packet);
        sendFxpPacket(packet);
    }

    private void sendFSETSTAT(@NonNull final byte[] handle,
                              @NonNull final SftpATTRS attr)
            throws IOException, GeneralSecurityException, SshChannelException {

        final Packet packet = createFxpPacket(SftpConstants.SSH_FXP_FSETSTAT)
                .putInt(seq++)
                .putString(handle);
        attr.putInto(packet);
        sendFxpPacket(packet);
    }

    private void sendSTATVFS(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath((byte) 0, str2byte(path), EXT_STATVFS_OPENSSH_COM);
    }

    private void sendMKDIR(@NonNull final String path,
                           @SuppressWarnings("SameParameterValue") @Nullable final SftpATTRS attr)
            throws IOException, GeneralSecurityException, SshChannelException {

        final byte[] _path = str2byte(path);
        final Packet packet = createFxpPacket(SftpConstants.SSH_FXP_MKDIR)
                .putInt(seq++)
                .putString(_path);
        if (attr != null) {
            attr.putInto(packet);
        } else {
            packet.putInt(0);
        }
        sendFxpPacket(packet);
    }

    private void sendRMDIR(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_RMDIR, str2byte(path), null);
    }

    private void sendREMOVE(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_REMOVE, str2byte(path), null);
    }

    private void sendSYMLINK(@NonNull final String p1,
                             @NonNull final String p2)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_SYMLINK, str2byte(p1), str2byte(p2), null);
    }

    private void sendHARDLINK(@NonNull final String p1,
                              @NonNull final String p2)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath((byte) 0, str2byte(p1), str2byte(p2), EXT_HARDLINK_OPENSSH_COM);
    }

    private void sendREADLINK(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_READLINK, str2byte(path), null);
    }

    private void sendREALPATH(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_REALPATH, str2byte(path), null);
    }

    /**
     * The SSH_FXP_OPENDIR opens a directory for reading.  It has the following format:
     * <p>
     * uint32     id
     * string     path
     * <p>
     * where `id' is the request identifier and `path' is the path name of
     * the directory to be listed (without any trailing slash).
     */
    private void sendOPENDIR(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_OPENDIR, str2byte(path), null);
    }

    private void sendREADDIR(@NonNull final byte[] handle)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_READDIR, handle, null);
    }

    private void sendRENAME(@NonNull final String p1,
                            @NonNull final String p2)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_RENAME, str2byte(p1), str2byte(p2),
                       extPosixRename ? EXT_POSIX_RENAME_OPENSSH_COM : null);
    }

    private void sendCLOSE(@NonNull final byte[] handle)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_CLOSE, handle, null);
    }

    private void sendOPENR(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendOPEN(path, SftpConstants.SSH_FXF_READ);
    }

    private void sendOPENW(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendOPEN(path, SftpConstants.SSH_FXF_WRITE | SftpConstants.SSH_FXF_CREAT
                | SftpConstants.SSH_FXF_TRUNC);
    }

    private void sendOPENA(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendOPEN(path,
                 SftpConstants.SSH_FXF_WRITE | SftpConstants.SSH_FXF_CREAT /* | SSH_FXF_APPEND */);
    }

    private void sendOPEN(@NonNull final String path,
                          final int mode)
            throws IOException, GeneralSecurityException, SshChannelException {

        final byte[] _path = str2byte(path);

        final Packet packet = createFxpPacket(SftpConstants.SSH_FXP_OPEN)
                .putInt(seq++)
                .putString(_path)
                .putInt(mode)
                // no attrs
                .putInt(0);
        sendFxpPacket(packet);
    }

    /**
     * Single path operations. e.g. REMOVE
     */
    private void sendPacketPath(final byte fxp,
                                @NonNull final byte[] path,
                                @Nullable final String extension)
            throws IOException, GeneralSecurityException, SshChannelException {

        final Packet packet;

        if (extension == null) {
            packet = createFxpPacket(fxp)
                    .putInt(seq++);
        } else {
            packet = createFxpPacket(SftpConstants.SSH_FXP_EXTENDED)
                    .putInt(seq++)
                    .putString(extension);
        }
        packet.putString(path);
        sendFxpPacket(packet);
    }

    /**
     * Dual-path operations. e.g. RENAME
     */
    private void sendPacketPath(final byte fxp,
                                @NonNull final byte[] path1,
                                @NonNull final byte[] path2,
                                @Nullable final String extension)
            throws IOException, GeneralSecurityException, SshChannelException {

        final Packet packet;

        if (extension == null) {
            packet = createFxpPacket(fxp)
                    .putInt(seq++);
        } else {
            packet = createFxpPacket(SftpConstants.SSH_FXP_EXTENDED)
                    .putInt(seq++)
                    .putString(extension);
        }
        packet.putString(path1)
              .putString(path2);
        sendFxpPacket(packet);
    }

    /**
     * @param handle file handle returned by {@link SftpConstants#SSH_FXP_OPEN}
     * @param offset the offset (in bytes) from the beginning of the file where to start writing
     * @param data   data to be written
     * @param start  the offset (in bytes) in the data buffer from where to start sending
     * @param length number of bytes we would like to send
     *               The actual amount can be lower and the caller must check
     *               the return value of this call.
     *
     * @return actual number of bytes send to the server
     */
    private int sendWRITE(@NonNull final byte[] handle,
                          final long offset,
                          @NonNull final byte[] data,
                          final int start,
                          final int length)
            throws IOException, GeneralSecurityException, SshChannelException {

        // Create on first use, re-use otherwise; the logic flow relies on that.
        if (uploadPacket == null) {
            uploadPacket = new Packet(localMaxPacketSize);
        }

        // Always write a clean header (remember, we re-use this packet!)
        uploadPacket.startCommand(SshConstants.SSH_MSG_CHANNEL_DATA)
                    .putInt(getRecipient())
                    .putInt(0xDEAD)
                    .putInt(0xBEEF)
                    .putByte(SftpConstants.SSH_FXP_WRITE)
                    .putInt(seq++)
                    .putString(handle)
                    .putLong(offset);

        // offset where the next set of file data will be written to the packet buffer
        final int dataOffset = WRITE_PACKET_HEADER_LEN + handle.length;
        // the amount of file data we can upload in this packet
        final int dataLength = Math.min(length,
                                        localMaxPacketSize - (dataOffset + Packet.SAFE_MARGIN));

        // optimization to avoid copying the array if possible
        // See #_put
        if (Arrays.equals(uploadPacket.data, data)) {
            uploadPacket.putInt(dataLength)
                        .moveWritePosition(dataLength);
        } else {
            uploadPacket.putString(data, start, dataLength);
        }
        sendFxpPacket(uploadPacket);

        return dataLength;
    }

    /**
     * Send a {@link SftpConstants#SSH_FXP_READ} request.
     *
     * @param handle an open file handle returned by {@link SftpConstants#SSH_FXP_OPEN}
     * @param offset the offset (in bytes) relative to the beginning of the file
     *               from where to start reading
     * @param length the maximum number of bytes to read
     * @param rrq    (optional) RequestQueue to use (used for sending parallel requests)
     */
    private void sendREAD(@NonNull final byte[] handle,
                          final long offset,
                          final int length,
                          @Nullable final RequestQueue rrq)
            throws IOException, GeneralSecurityException, SshChannelException {

        final Packet packet = createFxpPacket(SftpConstants.SSH_FXP_READ)
                .putInt(seq++)
                .putString(handle)
                .putLong(offset)
                .putInt(length);
        sendFxpPacket(packet);

        if (rrq != null) {
            rrq.add(seq - 1, offset, length);
        }
    }

    /**
     * Updates the header to complete the SSH_MSG_CHANNEL_DATA packet, and send it.
     *
     * @param packet FXP style packet to send
     */
    private void sendFxpPacket(@NonNull final Packet packet)
            throws SshChannelException, IOException, GeneralSecurityException {

        // length of the actual "data" blob == the length of the SFX packet
        final int payloadLength =
                packet.writeOffset - (Packet.HEADER_LEN + CHANNEL_PACKET_HEADER_LEN);

        // length of the "data" string in the SSH_MSG_CHANNEL_DATA header
        final int dataLength = 4 + payloadLength;

        // preserve current offset, and position after the recipient
        // top drop in the data and payload lengths
        final int writeOffset = packet.writeOffset;

        packet.setWriteOffSet(10)
              .putInt(dataLength)
              // "data": the SFX packet:
              // uint32             length
              .putInt(payloadLength)
              // restore the position
              .setWriteOffSet(writeOffset);

        sendChannelDataPacket(packet, dataLength);
    }

    /**
     * Create a packet used for <strong>sending</strong> SSH_SFX_* requests to the server.
     *
     * @param fxpType SSH_SFX_* command byte
     */
    private Packet createFxpPacket(final byte fxpType) {
        return new Packet(localMaxPacketSize)
                // byte      SSH_MSG_CHANNEL_DATA
                // uint32    recipient channel
                // string    data
                .startCommand(SshConstants.SSH_MSG_CHANNEL_DATA)
                .putInt(getRecipient())
                // We use place holders for the length fields. They will be updated at 'write' time
                // length of the "data" string: payloadLength + 4
                .putInt(0xDEAD)
                // "data": the SFX packet:
                // uint32             length: payloadLength
                // byte               type
                .putInt(0xBEEF)
                .putByte(fxpType);
    }

    /**
     * Read a <strong>FULL</strong>> packet from the input stream.
     * Check that the packet received is of the given expected type.
     * If it's not the expected type, an exception with the actual type byte will be thrown.
     * <p>
     * If it's a SSH_FXP_STATUS, it's assumed that the call succeeded, but returned
     * an error. An exception with the status code will be thrown.
     *
     * @param expectedType to check
     *
     * @return the received packet
     *
     * @throws SftpException either with the status, or with the wrong packet type.
     */
    @NonNull
    private FxpBuffer receive(final byte expectedType)
            throws SftpException {

        final FxpBuffer fxpBuffer = new FxpBuffer(remoteMaxPacketSize);
        try {
            //noinspection ConstantConditions
            fxpBuffer.readHeader(mpIn);
            fxpBuffer.readPayload(mpIn);
        } catch (final IOException e) {
            throw new SftpException(SftpConstants.SSH_FX_CONNECTION_LOST, e);
        }

        // check matching type first, we might have asked for the status only.
        if (fxpBuffer.getFxpType() == expectedType) {
            return fxpBuffer;

        } else if (fxpBuffer.getFxpType() == SftpConstants.SSH_FXP_STATUS) {
            final int status = fxpBuffer.getInt();
            throw createStatusException(fxpBuffer, status);

        } else {
            throw new SftpException(SftpConstants.SSH_FX_BAD_MESSAGE,
                                    ERROR_INVALID_TYPE_s + fxpBuffer.getFxpType());
        }
    }

    @NonNull
    private byte[] receiveNAME()
            throws IOException, SftpException {
        final FxpBuffer packet = receive(SftpConstants.SSH_FXP_NAME);
        packet.getInt(); // count, always 1
        return packet.getString();
    }

    @NonNull
    private byte[] receiveHANDLE()
            throws IOException, SftpException {
        final FxpBuffer packet = receive(SftpConstants.SSH_FXP_HANDLE);
        return packet.getString();
    }

    @NonNull
    private SftpStatVFS receiveStatVFS()
            throws SftpException {
        final FxpBuffer packet = receive(SftpConstants.SSH_FXP_EXTENDED_REPLY);
        return SftpStatVFS.getStatVFS(packet);
    }

    @NonNull
    private SftpATTRS receiveATTRS()
            throws IOException, SftpException {
        final FxpBuffer packet = receive(SftpConstants.SSH_FXP_ATTRS);
        return SftpATTRS.getATTR(packet);
    }

    /**
     * Read the next packet, and check if it is indeed a {@link SftpConstants#SSH_FXP_STATUS}.
     * and that the status is {@link SftpConstants#SSH_FX_OK}.
     *
     * @return the request id if the status was SSH_FX_OK
     *
     * @throws SftpException on all failures or bad packet/status.
     */
    private int checkStatus()
            throws SftpException {

        final FxpBuffer fxpBuffer = receive(SftpConstants.SSH_FXP_STATUS);
        final int status = fxpBuffer.getInt();
        if (status != SftpConstants.SSH_FX_OK) {
            throw createStatusException(fxpBuffer, status);
        }

        return fxpBuffer.getRequestId();
    }

    @NonNull
    private SftpException createStatusException(@NonNull final FxpBuffer packet,
                                                final int status) {
        String message;
        try {
            message = packet.getJString();
        } catch (final IOException e) {
            message = e.getMessage();
        }
        return new SftpException(status, message);
    }


    private void skip(long n)
            throws IOException {
        while (n > 0) {
            //noinspection ConstantConditions
            final long bytesSkipped = mpIn.skip(n);
            if (bytesSkipped <= 0) {
                // eof, we're done
                break;
            }
            n -= bytesSkipped;
        }
    }


    /**
     * Resolve the given path to a fully qualified remote single file or directory name.
     *
     * @param path to resolve
     *
     * @return fully qualified file or directory name
     *
     * @throws SftpException if resolving fails, or if it resolves to multiple names
     */
    @NonNull
    private String resolveRemotePath(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        final List<String> list = globRemotePath(path);
        if (list.size() != 1) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, path + " is not unique: " + list);
        }
        return list.get(0);
    }

    /**
     * If the given remote path is not already an absolute path,
     * make it one by prefixing it with the
     * <a href="#current-directory">current remote directory</a>.
     *
     * @param path to make absolute
     *
     * @return absolute path
     */
    @NonNull
    private String absoluteRemotePath(@NonNull final String path)
            throws SftpException {
        if (!path.isEmpty() && path.charAt(0) == '/') {
            return path;
        }

        final String dir = pwd();
        if (dir.endsWith("/")) {
            return dir + path;
        }
        return dir + "/" + path;
    }

    /**
     * If the given local path is not already an absolute path,
     * make it one by prefixing it with the
     * <a href="#current-directory">current local directory</a>.
     *
     * @param path to make absolute
     *
     * @return absolute path of which the file part MAY contain wildcards
     */
    @NonNull
    private String absoluteLocalPath(@NonNull final String path) {
        if (!path.isEmpty() && new File(path).isAbsolute()) {
            return path;
        }
        if (lcwd.endsWith(File.separator)) {
            return lcwd + path;
        }
        return lcwd + File.separator + path;
    }

    /**
     * Expand the pattern (if any) in the given path.
     *
     * @param path to expand
     *
     * @return expanded path(s)
     */
    @NonNull
    private List<String> globRemotePath(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        final String absPath = absoluteRemotePath(path);

        // split into directory and last part of the name, with (potentially) a pattern
        final int lastFileSepChar = absPath.lastIndexOf('/');
        final String dir = Globber.unquote(
                absPath.substring(0, lastFileSepChar == 0 ? 1 : lastFileSepChar));
        final String filenamePart = absPath.substring(lastFileSepChar + 1);

        // if we don't have a pattern, just return the reconstructed/unquoted path
        if (!Globber.isPattern(filenamePart)) {
            final List<String> list = new ArrayList<>();
            list.add((dir + "/") + Globber.unquote(filenamePart));
            return list;
        }

        // We have a pattern
        final byte[] _pattern = filenamePart.getBytes(StandardCharsets.UTF_8);

        // Ask the server to send us the dir listing. ('dir' must NOT have a trailing slash)
        sendOPENDIR(dir);
        final byte[] handle = receiveHANDLE();

        final List<String> list = new ArrayList<>();

        final FxpNamePacket fxpBuffer = new FxpNamePacket(remoteMaxPacketSize);
        while (true) {
            sendREADDIR(handle);

            //noinspection ConstantConditions
            fxpBuffer.decodeHeader(mpIn);

            int nrOfEntries = fxpBuffer.getNrOfEntries();
            if (nrOfEntries <= 0) {
                break;
            }

            while (nrOfEntries > 0) {
                fxpBuffer.fillBuffer(mpIn);

                final byte[] _filename = fxpBuffer.readString();

                if (glob(_pattern, _filename)) {
                    list.add((dir + "/") + byte2str(_filename));
                }
                nrOfEntries--;
            }
        }

        sendCLOSE(handle);
        checkStatus();
        return list;
    }

    /**
     * Expand the pattern (if any) in the given path.
     *
     * @param path to expand
     *
     * @return expanded path(s)
     */
    @NonNull
    private List<String> globLocalPath(@NonNull final String path) {
        return Globber.globAbsoluteLocalPath(absoluteLocalPath(path));
    }

    private boolean glob(@NonNull final byte[] pattern,
                         @NonNull final byte[] filename) {
        if (StandardCharsets.UTF_8.equals(fileNameEncoding)) {
            return Globber.glob(pattern, filename);
        } else {
            return Globber.glob(pattern, byte2str(filename).getBytes(StandardCharsets.UTF_8));
        }
    }

    @NonNull
    private byte[] str2byte(@NonNull final String str) {
        return str.getBytes(fileNameEncoding);
    }

    @NonNull
    private String byte2str(@NonNull final byte[] bytes) {
        return new String(bytes, 0, bytes.length, fileNameEncoding);
    }

    private static class QueuedRequest {

        int id;
        long offset;
        long length;
    }

    private static class OutOfOrderException
            extends Exception {

        private static final long serialVersionUID = 2605283687150522070L;
        final long offset;

        OutOfOrderException(final long offset) {
            this.offset = offset;
        }
    }

    private class RequestQueue {

        final QueuedRequest[] requestBuffer;
        int head;
        int count;

        RequestQueue(final int size) {
            requestBuffer = new QueuedRequest[size];
            for (int i = 0; i < requestBuffer.length; i++) {
                requestBuffer[i] = new QueuedRequest();
            }
        }

        void init() {
            head = 0;
            count = 0;
        }

        int count() {
            return count;
        }

        int size() {
            return requestBuffer.length;
        }

        void add(final int id,
                 final long offset,
                 final int length) {
            if (count == 0) {
                head = 0;
            }

            int tail = head + count;
            if (tail >= requestBuffer.length) {
                tail -= requestBuffer.length;
            }

            requestBuffer[tail].id = id;
            requestBuffer[tail].offset = offset;
            requestBuffer[tail].length = length;

            count++;
        }

        @NonNull
        QueuedRequest get(final int id)
                throws OutOfOrderException, SftpException {
            count--;

            final int i = head;

            head++;
            if (head == requestBuffer.length) {
                head = 0;
            }

            if (requestBuffer[i].id != id) {
                final long offset = getOffset();
                for (final QueuedRequest request : requestBuffer) {
                    if (request.id == id) {
                        request.id = 0;
                        throw new OutOfOrderException(offset);
                    }
                }
                throw new SftpException(SftpConstants.SSH_FX_BAD_MESSAGE,
                                        "RequestQueue: unknown request id " + id);
            }
            requestBuffer[i].id = 0;
            return requestBuffer[i];
        }

        private long getOffset() {
            long result = Long.MAX_VALUE;

            for (final QueuedRequest request : requestBuffer) {
                if (request.id != 0) {
                    if (result > request.offset) {
                        result = request.offset;
                    }
                }
            }
            return result;
        }

        void cancel()
                throws IOException {
            final int _count = count;
            // Remove outstanding data from the input stream
            final FxpBuffer fxpBuffer = new FxpBuffer(remoteMaxPacketSize);
            for (int i = 0; i < _count; i++) {
                //noinspection ConstantConditions
                fxpBuffer.readHeader(mpIn);
                for (final QueuedRequest request : requestBuffer) {
                    if (request.id == fxpBuffer.getRequestId()) {
                        request.id = 0;
                        break;
                    }
                }
                skip(fxpBuffer.getFxpLength());
            }
            init();
        }
    }
}
