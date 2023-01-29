package com.hardbacknutter.sshclient.channels.sftp;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.ChannelSftp;
import com.hardbacknutter.sshclient.ChannelSubsystem;
import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.channels.SshChannelException;
import com.hardbacknutter.sshclient.channels.io.MyPipedInputStream;
import com.hardbacknutter.sshclient.channels.session.ChannelSessionImpl;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.SessionImpl;
import com.hardbacknutter.sshclient.utils.Globber;
import com.hardbacknutter.sshclient.utils.SshConstants;

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
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * A Channel connected to an sftp server (as a subsystem of the ssh server).
 * <p>
 * This class supports the client side of the sftp protocol,
 * version 3, and implements an interface similar to the
 * usual {@code sftp} command line client.
 * <p>
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

    private static final String ERROR_MULTIPLE_FILES =
            "Copying multiple files, but the destination is missing or is a file.";
    private static final String ERROR_CANNOT_RESUME_s =
            "Size mismatch. Cannot resume ";
    private static final String ERROR_s_IS_A_DIRECTORY = " is a directory";
    private static final String ERROR_PATH_HAS_WILDCARDS_s = "Path has wildcards: ";
    private static final String ERROR_NO_SUCH_DIRECTORY = "No such directory";

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

    /** SftpConstants.SSH_FXP_OPEN mode. */
    private static final int OPEN_FOR_WRITE = SftpConstants.SSH_FXF_WRITE
            | SftpConstants.SSH_FXF_CREAT
            | SftpConstants.SSH_FXF_TRUNC;
    /** SftpConstants.SSH_FXP_OPEN mode. */
    private static final int OPEN_FOR_APPEND = SftpConstants.SSH_FXF_WRITE
            | SftpConstants.SSH_FXF_CREAT /* | SSH_FXF_APPEND */;
    /** SftpConstants.SSH_FXP_OPEN mode. */
    private static final int OPEN_FOR_READ = SftpConstants.SSH_FXF_READ;
    @NonNull
    private final RequestQueue requestQueue = new RequestQueue();
    /** <em>local current working directory</em>. */
    @NonNull
    private Path lcwd;
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
    /** the remote filename encoding as used on the server. */
    @NonNull
    private Charset remoteCharset = StandardCharsets.UTF_8;

    /** Package sequence counter. */
    private int seq = 1;

    @Nullable
    private MyPipedInputStream mpIn;

    /** Created when needed; then re-used until the channel is destroyed. */
    @Nullable
    private Packet uploadPacket;

    /**
     * Constructor.
     *
     * @param session {@link Session} instance this channel belongs to.
     */
    public ChannelSftpImpl(@NonNull final SessionImpl session) {
        super(session);
        lcwd = new File("").toPath();
    }

    /**
     * Expand the pattern (if any) in the given path.
     * <p>
     * (static to ease testing)
     *
     * @param path a path relative to the <em>current local directory</em>.
     *             The path can contain glob pattern wildcards {@code *} and {@code ?}
     *             in the last component (i.e. after the last file-separator char).
     *
     * @return a list of matching file-names.
     */
    @NonNull
    static List<String> expandLocalPattern(@NonNull final Path currentDir,
                                           @NonNull final String path) {
        // reminder:
        // We MUST manually concat/split the parts as the last part can hold a pattern!

        final String absPath;
        if (!path.isEmpty() && new File(path).isAbsolute()) {
            absPath = path;
        } else {
            absPath = currentDir.toString() + File.separatorChar + path;
        }

        final int i;
        if (File.separatorChar == '\\') {
            // Windows...
            i = Math.max(absPath.lastIndexOf('\\'), absPath.lastIndexOf('/'));
        } else {
            i = absPath.lastIndexOf(File.separatorChar);
        }

        final String dir;
        final String pattern;
        if (i >= 0) {
            dir = absPath.substring(0, i);
            pattern = absPath.substring(i + 1);
        } else {
            return new ArrayList<>();
        }

        // Note we're not using Files.newDirectoryStream as we want to enforce backwards
        // compatibility in Globber.globLocalPath
        final String[] children = new File(dir).list();
        if (children != null) {
            return Arrays.stream(children)
                         .filter(child -> Globber.globLocalPath(pattern, child))
                         .map(child -> new File(dir, child).getAbsolutePath())
                         .collect(Collectors.toList());

        }
        return new ArrayList<>();
    }

    @Override
    public void setFilenameEncoding(@NonNull final String encoding)
            throws UnsupportedEncodingException {
        try {
            remoteCharset = Charset.forName(encoding);
        } catch (final IllegalArgumentException e) {
            throw new UnsupportedEncodingException(encoding);
        }
    }

    /**
     * Convert the {@code byte[]} using the remote charset into a String.
     *
     * @param bytes to convert
     *
     * @return string
     */
    @NonNull
    private String byte2str(@NonNull final byte[] bytes) {
        return new String(bytes, 0, bytes.length, remoteCharset);
    }

    /**
     * Get the amount of requests which may be sent at any one time.
     *
     * @return how many requests may be sent at any one time.
     */
    public int getBulkRequests() {
        return requestQueue.getMaxSize();
    }

    /**
     * Specify how many requests may be sent at any one time.
     * Increasing this value may slightly improve file transfer speed but will
     * increase memory usage.  The default is 16 requests.
     *
     * @param maxRequests how many requests may be outstanding at any one time.
     */
    public void setBulkRequests(final int maxRequests) {
        requestQueue.init(maxRequests);
    }

    @Override
    protected void onAfterConnect(@NonNull final SessionImpl session)
            throws GeneralSecurityException, IOException, SshChannelException {

        final PipedOutputStream pos = new PipedOutputStream();
        setOutputStream(pos);

        mpIn = new MyPipedInputStream(pos, requestQueue.getMaxSize() * remoteMaxPacketSize);
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

        final Packet initPacket = createFxpPacket(SftpConstants.SSH_FXP_INIT)
                .putInt(CLIENT_VERSION);
        sendFxpPacket(initPacket);

        final FxpVersionPacket versionPacket = new FxpVersionPacket(remoteMaxPacketSize);
        versionPacket.decode(mpIn);

        server_version = versionPacket.getVersion();
        extensions = versionPacket.getExtensions();

        // http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD
        extPosixRename = "1".equals(extensions.get(EXT_POSIX_RENAME_OPENSSH_COM));
        exHardlink = "1".equals(extensions.get(EXT_HARDLINK_OPENSSH_COM));
        extStatvfs = "2".equals(extensions.get(EXT_STATVFS_OPENSSH_COM));
        extFstatvfs = "2".equals(extensions.get(EXT_FSTATVFS_OPENSSH_COM));
        extFsync = "1".equals(extensions.get(EXT_FSYNC_OPENSSH_COM));
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
        final Path absPath = lcwd.resolve(path);
        if (absPath.toFile().isDirectory()) {
            lcwd = absPath;
            return;
        }
        throw new SftpException(SftpConstants.SSH_FX_NO_SUCH_FILE, ERROR_NO_SUCH_DIRECTORY);
    }

    @Override
    @NonNull
    public String lpwd() {
        return lcwd.toString();
    }

    @Override
    public void cd(@NonNull final String path)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            final String absPath = resolveRemotePath(path);

            sendREALPATH(absPath);
            final byte[] remoteDir = receiveNAME();
            final String tmpCwd = byte2str(remoteDir);

            sendSTAT(remoteDir);
            final SftpATTRS attr = receiveATTRS();

            if ((attr.getFlags() & SftpATTRS.SSH_FILEXFER_ATTR_PERMISSIONS) == 0) {
                throw new SftpException(SftpConstants.SSH_FX_FAILURE, "Cannot cd to: " + tmpCwd);
            }
            if (!attr.isDirectory()) {
                throw new SftpException(SftpConstants.SSH_FX_FAILURE, "Not a directory: " + tmpCwd);
            }

            this.cwd = tmpCwd;

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
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            sendMKDIR(getAbsoluteRemotePath(path), null);
            checkStatus();
        } catch (final SftpException e) {
            throw e;
        } catch (final Exception e) {
            throw new SftpException(SftpConstants.SSH_FX_FAILURE, e);
        }
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
                    absNewPath = getAbsoluteRemotePath(newPath);
                    if (isPattern(absNewPath)) {
                        throw new SftpException(SftpConstants.SSH_FX_FAILURE,
                                                ERROR_PATH_HAS_WILDCARDS_s + absNewPath);
                    }
                    absNewPath = Globber.unescapePath(absNewPath);
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
    public List<LsEntry> ls(@NonNull final String path)
            throws SftpException {
        final List<LsEntry> entries = new ArrayList<>();
        final LsEntry.Selector selector = entry -> {
            entries.add(entry);
            return true;
        };

        ls(path, selector);
        return entries;
    }

    @Override
    public void ls(@NonNull final String path,
                   @NonNull final LsEntry.Selector selector)
            throws SftpException {
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            final String absPath = getAbsoluteRemotePath(path);

            // split into directory and last part of the name, with (potentially) a pattern
            final int sep = absPath.lastIndexOf('/');
            String dir = Globber.unescapePath(absPath.substring(0, sep == 0 ? 1 : sep));
            final String filenamePart = absPath.substring(sep + 1);

            final boolean patternHasWildcards = isPattern(filenamePart);
            final String pattern;
            if (patternHasWildcards) {
                pattern = filenamePart;

            } else {
                final String uPath = Globber.unescapePath(absPath);
                sendSTAT(uPath);
                final SftpATTRS attr = receiveATTRS();
                if (attr.isDirectory()) {
                    dir = uPath;
                    pattern = null;
                } else {
                    pattern = Globber.unescapePath(filenamePart);
                }
            }

            // Ask the server to send us the dir listing. 'dir' must NOT have a trailing slash
            sendOPENDIR(dir);
            final byte[] handle = receiveHANDLE();

            final FxpReadDirResponsePacket namePacket =
                    new FxpReadDirResponsePacket(remoteMaxPacketSize, server_version);

            FxpReadDirResponsePacket.LSStruct lsStruct;
            boolean keepReading = true;
            while (keepReading) {
                sendREADDIR(handle);
                int nrOfEntries = namePacket.readNrOfEntries(mpIn);
                keepReading = nrOfEntries > 0;

                while (nrOfEntries > 0 && keepReading) {
                    lsStruct = namePacket.readRawEntry(mpIn);

                    // filter the files we want based on the pattern
                    final boolean wanted;

                    if (pattern == null) {
                        wanted = true;

                    } else if (patternHasWildcards) {
                        final String filename = byte2str(lsStruct.filename);
                        wanted = Globber.globRemotePath(pattern, filename);

                    } else {
                        final String filename = byte2str(lsStruct.filename);
                        wanted = pattern.equals(filename);
                    }

                    if (wanted) {
                        final String longname;
                        if (lsStruct.longname == null) {
                            longname = null;
                        } else {
                            longname = byte2str(lsStruct.longname);
                        }

                        keepReading = selector.select(new LsEntryImpl(
                                byte2str(lsStruct.filename), longname, lsStruct.attr));
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
    public void ln(@NonNull final String targetPath,
                   @NonNull final String linkPath,
                   final boolean softLink)
            throws SftpException {
        if (!softLink && !exHardlink) {
            throw new SftpException(SftpConstants.SSH_FX_OP_UNSUPPORTED,
                                    EXT_HARDLINK_OPENSSH_COM + " not supported");
        }

        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            final String absTargetPath = resolveRemotePath(targetPath);
            final String absLinkPath = getAbsoluteRemotePath(linkPath);

            if (isPattern(absLinkPath)) {
                throw new SftpException(SftpConstants.SSH_FX_FAILURE,
                                        ERROR_PATH_HAS_WILDCARDS_s + absLinkPath);
            }

            if (softLink) {
                sendSYMLINK(absTargetPath, Globber.unescapePath(absLinkPath));
            } else {
                sendHARDLINK(absTargetPath, Globber.unescapePath(absLinkPath));
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

    @Override
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
            sendREALPATH(getAbsoluteRemotePath(path));
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
                           @Nullable final ProgressListener progressListener,
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
                progressListener.init(ChannelSftp.Direction.Get,
                                      srcFilename, "", srcAttr.getSize());
            }

            sendOPEN(srcFilename, OPEN_FOR_READ);
            final byte[] handle = receiveHANDLE();

            requestQueue.init();

            return new InputStream() {
                /** The buffer for multi-byte reads. */
                private final FxpBuffer fxpBuffer = new FxpBuffer(remoteMaxPacketSize);
                /**
                 * The amount of bytes we'll ask the server to send in each request.
                 * (Always try to fill the entire packet)
                 */
                private final int maxRequestLen = remoteMaxPacketSize - CHANNEL_PACKET_HEADER_LEN;
                /** Temporary buffer for reading a single byte of data. */
                private final byte[] singleByte = new byte[1];

                /** the offset in the remote file from where to read the next blob of data. */
                private long requestOffset = initialOffset;

                /** Flag set when close() has been called. */
                private boolean streamClosed;

                /** the remaining number of bytes we can/should read from the current packet. */
                private int remainingData;

                /**
                 * The buffer used to cache the data read.
                 * We always try to read as much as possible in one-go.
                 * The size of this buffer will be adjusted (made bigger) as/when needed.
                 */
                private byte[] cacheBuffer = new byte[COPY_BUFFER_SIZE];

                @Override
                public int read()
                        throws IOException {
                    if (streamClosed) {
                        return -1;
                    }
                    final int i = read(singleByte, 0, 1);
                    if (i == -1) {
                        return -1;
                    } else {
                        return singleByte[0] & 0xff;
                    }
                }

                @Override
                public int read(@NonNull final byte[] b,
                                final int off,
                                int len)
                        throws IOException {
                    if (streamClosed) {
                        return -1;
                    }

                    Objects.checkFromIndexSize(off, len, b.length);
                    if (len == 0) {
                        return 0;
                    }

                    // Read 'len' bytes as required from the cached buffer until exhausted.
                    if (remainingData > 0) {
                        // copy the requested 'len' or the remaining 'rest_len' bytes
                        // from the cache buffer to the output buffer
                        final int length = Math.min(remainingData, len);
                        System.arraycopy(cacheBuffer, 0, b, off, length);

                        // If there are more bytes left in the buffer,
                        if (remainingData - length > 0) {
                            // move them to the start of the cache buffer
                            System.arraycopy(cacheBuffer, length,
                                             cacheBuffer, 0,
                                             remainingData - length);
                        }

                        if (progressListener != null && !progressListener.count(length)) {
                            // we're cancelled
                            close();
                            return -1;
                        }

                        remainingData -= length;
                        return length;
                    }

                    // The cache was empty, we need to contact the server to get more data.
                    // Send as many requests in parallel as we can to speed things up
                    while (requestQueue.hasSpace()) {
                        try {
                            sendREAD(handle, requestOffset, maxRequestLen);
                        } catch (final IOException e) {
                            throw e;
                        } catch (final Exception e) {
                            throw new IOException(e);
                        }
                        requestOffset += maxRequestLen;
                    }

                    // start reading the next packet
                    fxpBuffer.readHeader(mpIn);
                    remainingData = fxpBuffer.getFxpLength();

                    final QueuedRequest queuedRequest;
                    try {
                        queuedRequest = requestQueue.get(fxpBuffer.getRequestId());
                    } catch (final OutOfOrderException e) {
                        requestOffset = e.offset;
                        //noinspection ResultOfMethodCallIgnored
                        skip(fxpBuffer.getFxpLength());
                        requestQueue.cancel();
                        return 0;

                    } catch (final SftpException e) {
                        throw new IOException(e);
                    }

                    // a status packet is a valid response
                    if (fxpBuffer.getFxpType() == SftpConstants.SSH_FXP_STATUS) {
                        try {
                            fxpBuffer.readPayload(mpIn);
                            final int status = fxpBuffer.getInt();
                            if (status == SftpConstants.SSH_FX_EOF) {
                                close();
                                return -1;

                            } else {
                                String message;
                                try {
                                    message = fxpBuffer.getJString();
                                } catch (final IOException e) {
                                    message = e.getMessage();
                                }
                                throw new SftpException(status, message);
                            }
                        } catch (final SftpException e) {
                            throw new IOException(e);
                        }
                    }

                    // but if we did not get a status or data packet, we have a problem
                    if (fxpBuffer.getFxpType() != SftpConstants.SSH_FXP_DATA) {
                        final SftpException cause = new SftpException(
                                SftpConstants.SSH_FX_BAD_MESSAGE,
                                ERROR_INVALID_TYPE_s + fxpBuffer.getFxpType());
                        throw new IOException(cause);
                    }

                    // Start processing the data packet

                    // Read the next field from the input stream for the current
                    // SSH_FXP_DATA packet which is the payload length.
                    final int payloadLength = fxpBuffer.readInt(mpIn);
                    remainingData -= 4;

                    /*
                     Since sftp protocol version 6, "end-of-file" has been defined,

                     byte   SSH_FXP_DATA
                     uint32 request-id
                     string data
                     bool   end-of-file [optional]

                     but some sftp server will send such a field in the sftp protocol 3,
                     so check if there are more bytes than expected
                     */
                    final int optionalDataToSkip = remainingData - payloadLength;

                    // limit the amount of bytes to fetch to the max package size.
                    len = Math.min(maxRequestLen, len);
                    // and again limit that to the actual payloadLength
                    len = Math.min(payloadLength, len);

                    // Read as much as we can of the data into the output buffer
                    int totalBytesRead = mpIn.read(b, off, len);
                    if (totalBytesRead == -1) {
                        // end-of-stream reached
                        return -1;
                    }

                    remainingData = payloadLength - totalBytesRead;

                    // If there is more data available, read it into the cache buffer.
                    if (remainingData > 0) {
                        if (cacheBuffer.length < remainingData) {
                            cacheBuffer = new byte[remainingData];
                        }

                        int bytesToRead = remainingData;
                        int offset = 0;
                        int bytesRead;
                        do {
                            bytesRead = mpIn.read(cacheBuffer, offset, bytesToRead);
                            if (bytesRead != -1) {
                                offset += bytesRead;
                                bytesToRead -= bytesRead;
                                totalBytesRead += bytesRead;
                            }
                        } while (bytesToRead > 0 && bytesRead != -1);
                    }

                    if (optionalDataToSkip > 0) {
                        //noinspection ResultOfMethodCallIgnored
                        mpIn.skip(optionalDataToSkip);
                    }

                    // Are we expecting even more data? If so, request the server for it.
                    if (payloadLength < queuedRequest.length) {
                        requestQueue.cancel();
                        try {
                            sendREAD(handle,
                                     queuedRequest.offset + payloadLength,
                                     (int) (queuedRequest.length - payloadLength)
                            );
                        } catch (final IOException e) {
                            throw e;
                        } catch (final Exception e) {
                            throw new IOException(e);
                        }
                        requestOffset = queuedRequest.offset + queuedRequest.length;
                    }

                    if (progressListener != null && !progressListener.count(totalBytesRead)) {
                        // we're cancelled
                        close();
                        return -1;
                    }

                    return totalBytesRead;
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
                    @Nullable final ProgressListener progressListener,
                    @NonNull final Mode mode)
            throws SftpException {

        File currentDestFile = null;
        try {
            //noinspection ConstantConditions
            mpIn.updateReadSide();

            // The destination MUST be a single name (i.e. no wildcards)
            // but MAY be either a file or a directory.
            final Path absDstPath = lcwd.resolve(dstPath);
            final boolean dstIsDirectory = absDstPath.toFile().isDirectory();

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
            // - ONE source file, and either a file or dir as destination;
            // - one or more source files, and a DIR as destination.
            for (final String absSrcPath : srcFilenames) {
                sendSTAT(absSrcPath);
                final SftpATTRS srcAttr = receiveATTRS();
                if (srcAttr.isDirectory()) {
                    throw new SftpException(SftpConstants.SSH_FX_OP_UNSUPPORTED,
                                            absSrcPath + ERROR_s_IS_A_DIRECTORY);
                }

                if (dstIsDirectory) {
                    // Combine local directory name + the remote filename
                    final int i = absSrcPath.lastIndexOf('/');
                    if (i == -1) {
                        currentDestFile = absDstPath.resolve(absSrcPath).toFile();
                    } else {
                        currentDestFile = absDstPath.resolve(absSrcPath.substring(i + 1)).toFile();
                    }
                } else {
                    currentDestFile = absDstPath.toFile();
                }

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

                if (progressListener != null) {
                    progressListener.init(ChannelSftp.Direction.Get,
                                          absSrcPath, currentDestFile.getName(),
                                          srcAttr.getSize());
                    if (mode == Mode.Resume) {
                        progressListener.count(dstFileSize);
                    }
                }

                try (final OutputStream fos =
                             new FileOutputStream(currentDestFile, mode != Mode.Overwrite)) {
                    _get(absSrcPath, fos, progressListener, mode, dstFileSize);
                }
                // reset when done!
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
                    @Nullable final ProgressListener progressListener,
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

            if (progressListener != null) {
                progressListener.init(ChannelSftp.Direction.Get,
                                      srcFilename, "", srcAttr.getSize());

                if (mode == Mode.Resume) {
                    progressListener.count(skip);
                }
            }

            _get(srcFilename, dstStream, progressListener, mode, skip);

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
     * @param srcFilename      the fully qualified remote source file name
     * @param dstStream        the destination output stream.
     * @param progressListener (optional) progress listener
     * @param mode             the transfer {@link Mode}
     * @param position         only used If the {@code mode} == {@code Mode#Resume} :
     *                         the position in the remote file where we should start the download
     */
    private void _get(@NonNull final String srcFilename,
                      @NonNull final OutputStream dstStream,
                      @Nullable final ProgressListener progressListener,
                      @NonNull final Mode mode,
                      final long position)
            throws SftpException, IOException {
        try {
            // single, fully qualified filename

            sendOPEN(srcFilename, OPEN_FOR_READ);
            final byte[] handle = receiveHANDLE();

            long offset = 0;
            if (mode == Mode.Resume) {
                offset = position;
            }

            requestQueue.init();

            // the offset in the remote file from where to read the next blob of data.
            long requestOffset = offset;

            // The amount of bytes we'll ask the server to send in each request.
            // (Always try to fill the entire packet)
            final int maxRequestLen = remoteMaxPacketSize - CHANNEL_PACKET_HEADER_LEN;

            final FxpBuffer fxpBuffer = new FxpBuffer(remoteMaxPacketSize);

            loop:
            while (true) {

                // send as many requests in parallel as we can to speed things up
                while (requestQueue.hasSpace()) {
                    sendREAD(handle, requestOffset, maxRequestLen);
                    requestOffset += maxRequestLen;
                }

                //noinspection ConstantConditions
                fxpBuffer.readHeader(mpIn);
                // the remaining number of bytes we can/should read from the current packet.
                int remainingData = fxpBuffer.getFxpLength();

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

                    } else {
                        String message;
                        try {
                            message = fxpBuffer.getJString();
                        } catch (final IOException e) {
                            message = e.getMessage();
                        }
                        throw new SftpException(status, message);
                    }
                }

                // but if we did not get a status or data packet, we have a problem
                if (fxpBuffer.getFxpType() != SftpConstants.SSH_FXP_DATA) {
                    break;
                }

                // Start processing the data packet

                // Read the next field from the input stream for the current
                // SSH_FXP_DATA packet which is the payload length.
                final int payloadLength = fxpBuffer.readInt(mpIn);
                remainingData -= 4;

                  /*
                     Since sftp protocol version 6, "end-of-file" has been defined,

                     byte   SSH_FXP_DATA
                     uint32 request-id
                     string data
                     bool   end-of-file [optional]

                     but some sftp server will send such a field in the sftp protocol 3,
                     so check if there are more bytes than expected
                     */
                final int optionalDataLen = remainingData - payloadLength;

                int bytesStillToRead = payloadLength;
                while (bytesStillToRead > 0) {
                    final int bytesRead = mpIn.read(fxpBuffer.data, 0,
                                                    Math.min(bytesStillToRead,
                                                             fxpBuffer.data.length));
                    if (bytesRead == -1) {
                        // end-of-stream reached
                        break loop;
                    }
                    // stream it forward to the user defined output stream
                    dstStream.write(fxpBuffer.data, 0, bytesRead);

                    offset += bytesRead;
                    bytesStillToRead -= bytesRead;

                    if (progressListener != null && !progressListener.count(bytesRead)) {
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
                             (int) (queuedRequest.length - payloadLength)
                    );
                    requestOffset = queuedRequest.offset + queuedRequest.length;
                }
            }
            dstStream.flush();

            if (progressListener != null) {
                progressListener.end();
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
                            @Nullable final ProgressListener progressListener,
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
                progressListener.init(ChannelSftp.Direction.Put,
                                      "", dstFilename, ProgressListener.UNKNOWN_SIZE);
            }

            if (mode == Mode.Overwrite) {

                sendOPEN(dstFilename, OPEN_FOR_WRITE);
            } else {

                sendOPEN(dstFilename, OPEN_FOR_APPEND);
            }
            final byte[] handle = receiveHANDLE();

            return new OutputStream() {
                /** Temporary buffer for writing a single byte of data. */
                private final byte[] singleByte = new byte[1];
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
                    singleByte[0] = (byte) w;
                    write(singleByte, 0, 1);
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
                    @Nullable final ProgressListener progressListener,
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
            final List<String> srcFilenames = expandLocalPattern(lcwd, srcFilename);
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
                    progressListener.init(ChannelSftp.Direction.Put,
                                          srcPath, dstFilename, new File(srcPath).length());
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
                    @Nullable final ProgressListener progressListener,
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
                progressListener.init(ChannelSftp.Direction.Put,
                                      "", dstFilename, ProgressListener.UNKNOWN_SIZE);
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
     * @param srcStream        the local source we want to upload
     * @param dstFilename      fully qualified remote single filename
     * @param progressListener (optional) progress listener
     * @param mode             the transfer {@link Mode}
     */
    private void _put(@NonNull final InputStream srcStream,
                      @NonNull final String dstFilename,
                      @Nullable final ProgressListener progressListener,
                      @NonNull final Mode mode)
            throws SftpException {

        // Create on first use, re-use otherwise; the logic flow relies on that.
        if (uploadPacket == null) {
            uploadPacket = new Packet(remoteMaxPacketSize);
        }

        // we can send multiple packets in parallel.
        final int maxRequests = requestQueue.getMaxSize();

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

                sendOPEN(dstFilename, OPEN_FOR_WRITE);
            } else {

                sendOPEN(dstFilename, OPEN_FOR_APPEND);
            }
            final byte[] handle = receiveHANDLE();

            // offset where the next set of file data will be written to the packet buffer
            final int dataOffset = WRITE_PACKET_HEADER_LEN + handle.length;
            // the amount of file data we can upload in this packet
            int dataLength = remoteMaxPacketSize - (dataOffset + safePacketMargin);

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
                    if (seq - 1 == startSeqId || seq - startSeqId - ackCount >= maxRequests) {

                        while (seq - startSeqId - ackCount >= maxRequests) {
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
                        dataLength = remoteMaxPacketSize - (dataOffset + safePacketMargin);
                    }
                }

                offset += totalBytes;

                if (progressListener != null && !progressListener.count(totalBytes)) {
                    break;
                }
            }

            final int _ackCount = seq - startSeqId;
            while (_ackCount > ackCount) {
                checkStatus();
                ackCount++;
            }

            if (progressListener != null) {
                progressListener.end();
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
        sendPacketPath(SftpConstants.SSH_FXP_STAT, path, null);
    }

    private void sendSTAT(@NonNull final byte[] path)
            throws IOException, GeneralSecurityException, SshChannelException {
        sendPacketPath(SftpConstants.SSH_FXP_STAT, path, null);
    }

    private void sendLSTAT(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {
        sendPacketPath(SftpConstants.SSH_FXP_LSTAT, path, null);
    }

    private void sendFSTAT(@NonNull final byte[] handle)
            throws IOException, GeneralSecurityException, SshChannelException {
        sendPacketPath(SftpConstants.SSH_FXP_FSTAT, handle, null);
    }

    private void sendSETSTAT(@NonNull final String path,
                             @NonNull final SftpATTRS attr)
            throws IOException, GeneralSecurityException, SshChannelException {

        final Packet packet = createFxpPacket(SftpConstants.SSH_FXP_SETSTAT)
                .putInt(seq++)
                .putString(path, remoteCharset);
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
        sendPacketPath((byte) 0, path, EXT_STATVFS_OPENSSH_COM);
    }

    private void sendMKDIR(@NonNull final String path,
                           @SuppressWarnings("SameParameterValue") @Nullable final SftpATTRS attr)
            throws IOException, GeneralSecurityException, SshChannelException {

        final Packet packet = createFxpPacket(SftpConstants.SSH_FXP_MKDIR)
                .putInt(seq++)
                .putString(path, remoteCharset);
        if (attr != null) {
            attr.putInto(packet);
        } else {
            packet.putInt(0);
        }
        sendFxpPacket(packet);
    }

    private void sendRMDIR(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {
        sendPacketPath(SftpConstants.SSH_FXP_RMDIR, path, null);
    }

    private void sendREMOVE(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {
        sendPacketPath(SftpConstants.SSH_FXP_REMOVE, path, null);
    }

    private void sendSYMLINK(@NonNull final String p1,
                             @NonNull final String p2)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_SYMLINK, p1, p2, null);
    }

    private void sendHARDLINK(@NonNull final String p1,
                              @NonNull final String p2)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath((byte) 0, p1, p2, EXT_HARDLINK_OPENSSH_COM);
    }

    private void sendREADLINK(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_READLINK, path, null);
    }

    private void sendREALPATH(@NonNull final String path)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_REALPATH, path, null);
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

        sendPacketPath(SftpConstants.SSH_FXP_OPENDIR, path, null);
    }

    private void sendREADDIR(@NonNull final byte[] handle)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_READDIR, handle, null);
    }

    private void sendRENAME(@NonNull final String p1,
                            @NonNull final String p2)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_RENAME, p1, p2,
                       extPosixRename ? EXT_POSIX_RENAME_OPENSSH_COM : null);
    }

    private void sendCLOSE(@NonNull final byte[] handle)
            throws IOException, GeneralSecurityException, SshChannelException {

        sendPacketPath(SftpConstants.SSH_FXP_CLOSE, handle, null);
    }

    private void sendOPEN(@NonNull final String path,
                          final int mode)
            throws IOException, GeneralSecurityException, SshChannelException {

        final Packet packet = createFxpPacket(SftpConstants.SSH_FXP_OPEN)
                .putInt(seq++)
                .putString(path, remoteCharset)
                .putInt(mode)
                // no attrs
                .putInt(0);
        sendFxpPacket(packet);
    }

    /**
     * Single path operations. e.g. REMOVE
     */
    private void sendPacketPath(final byte fxp,
                                @NonNull final String path,
                                @Nullable final String extension)
            throws IOException, GeneralSecurityException, SshChannelException {
        sendPacketPath(fxp, path.getBytes(remoteCharset), extension);
    }

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
                                @NonNull final String path1,
                                @NonNull final String path2,
                                @Nullable final String extension)
            throws IOException, GeneralSecurityException, SshChannelException {
        sendPacketPath(fxp, path1.getBytes(remoteCharset), path2.getBytes(remoteCharset),
                       extension);
    }

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
            uploadPacket = new Packet(remoteMaxPacketSize);
        }

        // Always write a clean header (remember, we re-use this packet!)
        uploadPacket.init(SshConstants.SSH_MSG_CHANNEL_DATA)
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
                                        remoteMaxPacketSize - (dataOffset + safePacketMargin));

        // optimization to avoid copying the array if possible
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
     */
    private void sendREAD(@NonNull final byte[] handle,
                          final long offset,
                          final int length)
            throws IOException, GeneralSecurityException, SshChannelException {

        final Packet packet = createFxpPacket(SftpConstants.SSH_FXP_READ)
                .putInt(seq)
                .putString(handle)
                .putLong(offset)
                .putInt(length);
        sendFxpPacket(packet);

        requestQueue.add(seq, offset, length);
        seq++;
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
        return new Packet(remoteMaxPacketSize)
                // byte      SSH_MSG_CHANNEL_DATA
                // uint32    recipient channel
                // string    data
                .init(SshConstants.SSH_MSG_CHANNEL_DATA)
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
            if (bytesSkipped > 0) {
                n -= bytesSkipped;
            } else {
                // eof, we're done
                n = 0;
            }
        }
    }

    /**
     * Check if the given path has <strong>un-escaped</strong> wildcards.
     *
     * @param path to check
     *
     * @return {@code true} if this path represents a pattern
     */
    private boolean isPattern(@NonNull final String path) {
        final byte[] pathBytes = path.getBytes(StandardCharsets.UTF_8);

        final int length = pathBytes.length;
        int i = 0;
        while (i < length) {
            if (pathBytes[i] == '*' || pathBytes[i] == '?') {
                return true;
            }
            if (pathBytes[i] == '\\' && i + 1 < length) {
                // skip the next char, it's escaped
                i++;
            }
            i++;
        }
        return false;
    }

    /**
     * If the given remote path is not already an absolute path,
     * make it one by prefixing it with the <em>current remote directory</em>.
     *
     * @param path to make absolute
     *
     * @return absolute path
     */
    @NonNull
    private String getAbsoluteRemotePath(@NonNull final String path)
            throws SftpException {
        if (path.startsWith("/")) {
            return path;
        }

        final String tmpCwd = pwd();
        if (tmpCwd.endsWith("/")) {
            return tmpCwd + path;
        }
        return tmpCwd + '/' + path;
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
        if (list.size() == 1) {
            return list.get(0);
        }
        throw new SftpException(SftpConstants.SSH_FX_FAILURE, path + " is not unique: " + list);
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

        final String absPath = getAbsoluteRemotePath(path);

        // split into directory and last part of the name, with (potentially) a pattern
        final int sep = absPath.lastIndexOf('/');
        final String dir = Globber.unescapePath(absPath.substring(0, sep == 0 ? 1 : sep));
        final String filenamePart = absPath.substring(sep + 1);

        // if we don't have a pattern, just return the reconstructed/unquoted path
        if (!isPattern(filenamePart)) {
            final List<String> list = new ArrayList<>();
            list.add(dir + "/" + Globber.unescapePath(filenamePart));
            return list;
        }

        // filenamePart is a pattern

        // Ask the server to send us the dir listing. ('dir' must NOT have a trailing slash)
        sendOPENDIR(dir);
        final byte[] handle = receiveHANDLE();

        final List<String> results = new ArrayList<>();

        final FxpReadDirResponsePacket namePacket =
                new FxpReadDirResponsePacket(remoteMaxPacketSize, server_version);

        FxpReadDirResponsePacket.LSStruct tmpLsStruct;
        boolean keepReading = true;
        while (keepReading) {
            sendREADDIR(handle);
            //noinspection ConstantConditions
            int nrOfEntries = namePacket.readNrOfEntries(mpIn);
            keepReading = nrOfEntries > 0;

            while (nrOfEntries > 0) {
                tmpLsStruct = namePacket.readRawEntry(mpIn);

                final String filename = byte2str(tmpLsStruct.filename);
                if (Globber.globRemotePath(filenamePart, filename)) {
                    results.add((dir + "/") + filename);
                }
                nrOfEntries--;
            }
        }

        sendCLOSE(handle);
        checkStatus();
        return results;
    }

    private static class QueuedRequest {
        final int id;
        final long offset;
        final long length;

        /**
         * Constructor.
         *
         * @param id     Package sequence id
         * @param offset the offset (in bytes) relative to the beginning of the file
         *               from where the packet is requesting to start reading
         * @param length the maximum number of bytes to read overall
         */
        QueuedRequest(final int id,
                      final long offset,
                      final long length) {
            this.id = id;
            this.offset = offset;
            this.length = length;
        }
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

        private static final int DEFAULT_SIZE = 16;
        private final List<QueuedRequest> requestBuffer = new LinkedList<>();
        private int maxSize = DEFAULT_SIZE;

        RequestQueue() {
        }

        void init() {
            requestBuffer.clear();
        }

        void init(final int maxSize) {
            if (maxSize > 0) {
                this.maxSize = maxSize;
            } else {
                this.maxSize = DEFAULT_SIZE;
            }
            requestBuffer.clear();
        }


        boolean hasSpace() {
            return requestBuffer.size() < maxSize;
        }

        int getMaxSize() {
            return maxSize;
        }

        void add(final int id,
                 final long offset,
                 final int length) {
            requestBuffer.add(new QueuedRequest(id, offset, length));
        }

        @NonNull
        QueuedRequest get(final int id)
                throws OutOfOrderException, SftpException {

            final QueuedRequest current = requestBuffer.get(0);
            if (current.id == id) {
                requestBuffer.remove(0);
                return current;

            } else {
                final Optional<QueuedRequest> req = requestBuffer
                        .stream().filter(p -> p.id == id).findFirst();
                if (req.isPresent()) {
                    // We found the packet id we were actually looking for,
                    // but not in the order we expected.
                    // Calculate the offset from where we should/could continue
                    // the download if another attempt is done.
                    final long offset = requestBuffer
                            .stream()
                            .mapToLong(request -> request.offset)
                            .min()
                            .orElse(Long.MAX_VALUE);
                    throw new OutOfOrderException(offset);

                } else {
                    throw new SftpException(SftpConstants.SSH_FX_BAD_MESSAGE,
                                            "RequestQueue: unknown request id " + id);
                }
            }
        }

        void cancel()
                throws IOException {
            final int count = requestBuffer.size();
            if (count > 0) {
                // Remove all outstanding data from the input stream
                final FxpBuffer fxpBuffer = new FxpBuffer(remoteMaxPacketSize);
                for (int i = 0; i < count; i++) {
                    //noinspection ConstantConditions
                    fxpBuffer.readHeader(mpIn);
                    skip(fxpBuffer.getFxpLength());
                }
                // and clear the queue
                init();
            }
        }
    }
}
