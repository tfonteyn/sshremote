package com.hardbacknutter.sshclient.channels.sftp;

import androidx.annotation.NonNull;

@SuppressWarnings({"WeakerAccess", "unused"})
public final class SftpStatVFS {

    /** statvfs@openssh.com f_flag flags */
    private static final int SSH2_FXE_STATVFS_ST_RDONLY = 0x00000001;
    private static final int SSH2_FXE_STATVFS_ST_NOSUID = 0x00000002;

    /** read-only file system */
    private static final int ST_RDONLY = 0x01;
    /** does not support setuid/setgid semantics */
    private static final int ST_NOSUID = 0x02;
    /** does not truncate file names longer than NAME_MAX */
    private static final int ST_NOTRUNC = 0x04;

    private long bsize;
    private long frsize;
    private long blocks;
    private long bfree;
    private long bavail;
    private long files;
    private long ffree;
    private long favail;
    private long fsid;
    private long flag;
    private long namemax;

    private SftpStatVFS() {
    }

    static SftpStatVFS getStatVFS(@NonNull final FxpBuffer fxpBuffer) {
        final SftpStatVFS statvfs = new SftpStatVFS();

        statvfs.bsize = fxpBuffer.getLong();
        statvfs.frsize = fxpBuffer.getLong();
        statvfs.blocks = fxpBuffer.getLong();
        statvfs.bfree = fxpBuffer.getLong();
        statvfs.bavail = fxpBuffer.getLong();
        statvfs.files = fxpBuffer.getLong();
        statvfs.ffree = fxpBuffer.getLong();
        statvfs.favail = fxpBuffer.getLong();
        statvfs.fsid = fxpBuffer.getLong();
        final int flag = (int) fxpBuffer.getLong();
        statvfs.namemax = fxpBuffer.getLong();

        statvfs.flag = ((flag & SSH2_FXE_STATVFS_ST_RDONLY) != 0 ? ST_RDONLY : 0)
                | ((flag & SSH2_FXE_STATVFS_ST_NOSUID) != 0 ? ST_NOSUID : 0);

        return statvfs;
    }

    public long getBlockSize() {
        return bsize;
    }

    public long getFragmentSize() {
        return frsize;
    }

    public long getBlocks() {
        return blocks;
    }

    public long getFreeBlocks() {
        return bfree;
    }

    public long getAvailBlocks() {
        return bavail;
    }

    public long getINodes() {
        return files;
    }

    public long getFreeINodes() {
        return ffree;
    }

    public long getAvailINodes() {
        return favail;
    }

    public long getFileSystemID() {
        return fsid;
    }

    public long getMountFlag() {
        return flag;
    }

    public long getMaximumFilenameLength() {
        return namemax;
    }

    public long getSize() {
        return getFragmentSize() * getBlocks() / 1024;
    }

    public long getUsed() {
        return getFragmentSize() * (getBlocks() - getFreeBlocks()) / 1024;
    }

    public long getAvailForNonRoot() {
        return getFragmentSize() * getAvailBlocks() / 1024;
    }

    public long getAvail() {
        return getFragmentSize() * getFreeBlocks() / 1024;
    }

    public int getCapacity() {
        return (int) (100 * (getBlocks() - getFreeBlocks()) / getBlocks());
    }
}
