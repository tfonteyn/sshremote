package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;

public class DbgSftpProgressMonitor
        implements ChannelSftp.SftpProgressMonitor {

    private final Logger mLogger;

    DbgSftpProgressMonitor() {
        mLogger = SshClient.getLogger();
    }

    @Override
    public void init(final int op,
                     @NonNull final String src,
                     @NonNull final String dest,
                     final long max) {
        mLogger.log(Logger.INFO, "Progress: op=" + op
                + ", src=" + src + ", dst=" + dest + ", max=" + max);
    }

    @Override
    public boolean count(final long count) {
        mLogger.log(Logger.INFO, "Progress: count=" + count);
        return true;
    }

    @Override
    public void end() {
        mLogger.log(Logger.INFO, "Progress: END");
    }
}
