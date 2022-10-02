package com.hardbacknutter.sshclient.channels.sftp;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.ChannelSftp;
import com.hardbacknutter.sshclient.transport.Packet;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;

/**
 * Attributes of a (remote) file manipulated via Sftp.
 * An SftpATTRS object can contain a variable number of actual
 * attributes. A {@code flags} field defines which attributes
 * are present in the structure, and then only these follow.
 * <p>
 * This class manages the flags automatically, the setXXX methods
 * also set the corresponding flag.
 * </p>
 * <p>
 * When changing attributes using
 * {@link ChannelSftp#setStat ChannelSftp.setStat()}, only these
 * attributes actually contained in the structure are sent to the
 * server and will be changed.
 * </p>
 * <p>
 * This class corresponds to the ATTRS structure in the form defined
 * in
 * <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-5">
 * version 00-02 of the Internet draft <em>SSH File Transfer Protocol</em></a>,
 * corresponding to version 3 of the SSH File transfer protocol.
 * (Later versions changed the format, and there is no version actually
 * published as RFC.)
 * </p>
 * Here is a quote from the specification:
 * <pre>
 *   uint32   flags
 *   uint64   size           present only if flag SSH_FILEXFER_ATTR_SIZE
 *   uint32   uid            present only if flag SSH_FILEXFER_ATTR_UIDGID
 *   uint32   gid            present only if flag SSH_FILEXFER_ATTR_UIDGID
 *   uint32   permissions    present only if flag SSH_FILEXFER_ATTR_PERMISSIONS
 *   uint32   atime          present only if flag SSH_FILEXFER_ACMODTIME
 *   uint32   mtime          present only if flag SSH_FILEXFER_ACMODTIME
 *   uint32   extended_count present only if flag SSH_FILEXFER_ATTR_EXTENDED
 *   string   extended_type
 *   string   extended_data
 *     ...      more extended data (extended_type - extended_data pairs),
 *              so that number of pairs equals extended_count
 * </pre>
 *
 * @see ChannelSftp
 * @see ChannelSftp#stat stat()
 * @see ChannelSftp#lstat lstat()
 * @see ChannelSftp#setStat setStat()
 */
@SuppressWarnings({"OctalInteger", "WeakerAccess", "unused"})
public final class SftpATTRS {

    /**
     * Flag indicating the presence of the {@link #getPermissions permissions} attribute.
     */
    public static final int SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
    /**
     * Flag indicating the presence of the {@link #getSize size} attribute.
     */
    public static final int SSH_FILEXFER_ATTR_SIZE = 0x00000001;
    /**
     * Flag indicating the presence of the {@link #getUid uid}
     * and {@link #getGid gid} attributes.
     */
    public static final int SSH_FILEXFER_ATTR_UIDGID = 0x00000002;
    /**
     * Flag indicating the presence of the {@link #getATime atime}
     * and {@link #getMTime mtime} attributes.
     */
    public static final int SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008;
    /**
     * Flag indicating the presence of {@linkplain #getExtended extended attributes}.
     */
    public static final int SSH_FILEXFER_ATTR_EXTENDED = 0x80000000;

    // These are octal numbers!
    private static final int S_ISUID = 04000; // set user ID on execution
    private static final int S_ISGID = 02000; // set group ID on execution
    private static final int S_ISVTX = 01000; // sticky bit   ****** NOT DOCUMENTED *****
    private static final int S_IRUSR = 00400; // read by owner
    private static final int S_IWUSR = 00200; // write by owner
    private static final int S_IXUSR = 00100; // execute/search by owner
    private static final int S_IREAD = 00400; // read by owner
    private static final int S_IWRITE = 00200; // write by owner
    private static final int S_IEXEC = 00100; // execute/search by owner
    private static final int S_IRGRP = 00040; // read by group
    private static final int S_IWGRP = 00020; // write by group
    private static final int S_IXGRP = 00010; // execute/search by group
    private static final int S_IROTH = 00004; // read by others
    private static final int S_IWOTH = 00002; // write by others
    private static final int S_IXOTH = 00001; // execute/search by others

    // but these are hex.
    private static final int S_IFMT = 0xf000;
    private static final int S_IFIFO = 0x1000;
    private static final int S_IFCHR = 0x2000;
    private static final int S_IFDIR = 0x4000;
    private static final int S_IFBLK = 0x6000;
    private static final int S_IFREG = 0x8000;
    private static final int S_IFLNK = 0xa000;
    private static final int S_IFSOCK = 0xc000;

    /**
     * The bitmask containing all the bits defined above,
     * but not the link or directory bits.
     */
    private static final int pmask = 0xFFF;
    private int uid;
    private int gid;
    private int flags;
    private long size;
    private int permissions;
    private int atime;
    private int mtime;
    private String[] extended;

    private SftpATTRS() {
    }

    /**
     * Factory constructor.
     * <p>
     * Parses an ATTR structure from a buffer.
     */
    static SftpATTRS getATTR(@NonNull final FxpBuffer fxpBuffer)
            throws IOException {
        final SftpATTRS attr = new SftpATTRS();
        attr.flags = fxpBuffer.getInt();
        if ((attr.flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
            attr.size = fxpBuffer.getLong();
        }
        if ((attr.flags & SSH_FILEXFER_ATTR_UIDGID) != 0) {
            attr.uid = fxpBuffer.getInt();
            attr.gid = fxpBuffer.getInt();
        }
        if ((attr.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            attr.permissions = fxpBuffer.getInt();
        }
        if ((attr.flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
            attr.atime = fxpBuffer.getInt();
        }
        if ((attr.flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
            attr.mtime = fxpBuffer.getInt();
        }
        if ((attr.flags & SSH_FILEXFER_ATTR_EXTENDED) != 0) {
            final int count = fxpBuffer.getInt();
            if (count > 0) {
                attr.extended = new String[count * 2];
                for (int i = 0; i < count; i++) {
                    attr.extended[i * 2] = fxpBuffer.getJString();
                    attr.extended[i * 2 + 1] = fxpBuffer.getJString();
                }
            }
        }
        return attr;
    }

    /**
     * Returns a string representation of the permissions
     * in the format used by {@code ls -l}.
     */
    public String getPermissionsString() {
        final StringBuilder sb = new StringBuilder(10);

        if (isDirectory()) {
            sb.append('d');
        } else if (isLink()) {
            sb.append('l');
        } else {
            sb.append('-');
        }

        if ((permissions & S_IRUSR) != 0) {
            sb.append('r');
        } else {
            sb.append('-');
        }

        if ((permissions & S_IWUSR) != 0) {
            sb.append('w');
        } else {
            sb.append('-');
        }

        if ((permissions & S_ISUID) != 0) {
            sb.append('s');
        } else if ((permissions & S_IXUSR) != 0) {
            sb.append('x');
        } else {
            sb.append('-');
        }

        if ((permissions & S_IRGRP) != 0) {
            sb.append('r');
        } else {
            sb.append('-');
        }

        if ((permissions & S_IWGRP) != 0) {
            sb.append('w');
        } else {
            sb.append('-');
        }

        if ((permissions & S_ISGID) != 0) {
            sb.append('s');
        } else if ((permissions & S_IXGRP) != 0) {
            sb.append('x');
        } else {
            sb.append('-');
        }

        if ((permissions & S_IROTH) != 0) {
            sb.append('r');
        } else {
            sb.append('-');
        }

        if ((permissions & S_IWOTH) != 0) {
            sb.append('w');
        } else {
            sb.append('-');
        }

        if ((permissions & S_IXOTH) != 0) {
            sb.append('x');
        } else {
            sb.append('-');
        }
        return sb.toString();
    }

    /**
     * returns a string representation of the access time.
     */
    @SuppressWarnings({"UseOfObsoleteDateTimeApi", "CallToDateToString"})
    public String getAccessTimeString() {
        final Date date = new Date((long) atime * 1000L);
        return date.toString();
    }

    /**
     * returns a string representation of the modification time.
     */
    @SuppressWarnings({"UseOfObsoleteDateTimeApi", "CallToDateToString"})
    public String getModificationTimeString() {
        final Date date = new Date((long) mtime * 1000L);
        return date.toString();
    }

    /**
     * writes the ATTR structure to a Packet.
     */
    void putInto(@NonNull final Packet packet) {
        packet.putInt(flags);
        if ((flags & SSH_FILEXFER_ATTR_SIZE) != 0) {
            packet.putLong(size);
        }
        if ((flags & SSH_FILEXFER_ATTR_UIDGID) != 0) {
            packet.putInt(uid)
                  .putInt(gid);
        }
        if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
            packet.putInt(permissions);
        }
        if ((flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
            packet.putInt(atime);
        }
        if ((flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0) {
            packet.putInt(mtime);
        }
        if ((flags & SSH_FILEXFER_ATTR_EXTENDED) != 0) {
            final int count = extended.length / 2;
            if (count > 0) {
                for (int i = 0; i < count; i++) {
                    packet.putString(extended[i * 2])
                          .putString(extended[i * 2 + 1]);
                }
            }
        }
    }

    /**
     * sets the flags indicating which fields are included.
     */
    void setFLAGS(@SuppressWarnings("SameParameterValue") final int flags) {
        this.flags = flags;
    }

    /**
     * sets the size.
     */
    public void setSIZE(final long size) {
        flags |= SSH_FILEXFER_ATTR_SIZE;
        this.size = size;
    }

    /**
     * Sets user and group Identifier.
     */
    void setUIDGID(final int uid,
                   final int gid) {
        flags |= SSH_FILEXFER_ATTR_UIDGID;
        this.uid = uid;
        this.gid = gid;
    }

    /**
     * Sets access and modification time.
     */
    void setACMODTIME(final int atime,
                      final int mtime) {
        flags |= SSH_FILEXFER_ATTR_ACMODTIME;
        this.atime = atime;
        this.mtime = mtime;
    }

    /**
     * sets the file permissions.
     *
     * @param permissions a bit mask containing some combination
     *                    of the bits 0-11.
     */
    void setPERMISSIONS(final int permissions) {
        flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        this.permissions = this.permissions & ~pmask | permissions & pmask;
    }

    public boolean isType(final int mask) {
        return (flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 &&
                (permissions & S_IFMT) == mask;
    }

    public boolean isReg() {
        return isType(S_IFREG);
    }

    /**
     * checks whether this file is a directory.
     *
     * @return {@code true} if the permissions are included in the
     * structure and the directory bit is set.
     */
    public boolean isDirectory() {
        return isType(S_IFDIR);
    }

    public boolean isChr() {
        return isType(S_IFCHR);
    }

    public boolean isBlk() {
        return isType(S_IFBLK);
    }

    public boolean isFifo() {
        return isType(S_IFIFO);
    }

    /**
     * checks whether this file is a symbolic link.
     *
     * @return {@code true} if the permissions are included in the
     * structure and the link bits are set.
     */
    public boolean isLink() {
        return isType(S_IFLNK);
    }

    public boolean isSock() {
        return isType(S_IFSOCK);
    }

    /**
     * returns the flags indicating which attributes
     * are present.
     */
    public int getFlags() {
        return flags;
    }

    /**
     * Returns the size of the file, in bytes.
     */
    public long getSize() {
        return size;
    }

    /**
     * returns the numerical user identifier of the owning user.
     * <blockquote>
     * The `uid' and `gid' fields contain numeric Unix-like user and group
     * identifiers, respectively.
     * </blockquote>
     */
    public int getUid() {
        return uid;
    }

    /**
     * returns the numerical group identifier of the owning group.
     * <blockquote>
     * The `uid' and `gid' fields contain numeric Unix-like user and group
     * identifiers, respectively.
     * </blockquote>
     */
    public int getGid() {
        return gid;
    }

    /**
     * Returns the Unix permissions of the file.
     * <blockquote>
     * The `permissions' field contains a bit mask of file permissions as
     * defined by posix.
     * </blockquote>
     */
    @SuppressWarnings("WeakerAccess")
    public int getPermissions() {
        return permissions;
    }

    /**
     * returns the last access time.
     * <blockquote>
     * The `atime' and `mtime' contain the access and modification times of
     * the files, respectively.  They are represented as seconds from Jan 1,
     * 1970 in UTC.
     * </blockquote>
     */
    public int getATime() {
        return atime;
    }

    /**
     * returns the last modification time.
     * <blockquote>
     * The `atime' and `mtime' contain the access and modification times of
     * the files, respectively.  They are represented as seconds from Jan 1,
     * 1970 in UTC.
     * </blockquote>
     */
    public int getMTime() {
        return mtime;
    }

    /**
     * returns extended attributes, if any.
     *
     * @return the attributes, in the form of a string array, alternating
     * type identifier and value.
     */
    public String[] getExtended() {
        return extended;
    }

    /**
     * creates a string representation of this object.
     * This string contains permissions, UID, GID, size and modification time.
     */
    public String getAsString() {
        return getPermissionsString()
                + " " + getUid()
                + " " + getGid()
                + " " + getSize()
                + " " + getModificationTimeString();
    }

    @Override
    public String toString() {
        return "SftpATTRS{" +
                "uid=" + uid +
                ", gid=" + gid +
                ", flags=0b" + Integer.toBinaryString(flags) +
                ", size=" + size +
                ", permissions=" + getPermissionsString() +
                ", atime=" + getAccessTimeString() +
                ", mtime=" + getModificationTimeString() +
                ", extended=" + Arrays.toString(extended) +
                '}';
    }
}
