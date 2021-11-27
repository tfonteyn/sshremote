/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2002-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package com.hardbackcollector.sshclient.channels.sftp;

import androidx.annotation.NonNull;

public final class SftpStatVFS {

    /* statvfs@openssh.com f_flag flags */
    private static final int SSH2_FXE_STATVFS_ST_RDONLY = 0x00000001;
    private static final int SSH2_FXE_STATVFS_ST_NOSUID = 0x00000002;

    /* read-only file system */
    private static final int ST_RDONLY = 0x01;
    /* does not support setuid/setgid semantics */
    private static final int ST_NOSUID = 0x02;
    /* does not truncate file names longer than NAME_MAX */
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
