package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;

public class DbgProgressListener
        implements ChannelSftp.ProgressListener {

    private final Logger logger;

    public DbgProgressListener(@NonNull final Session session) {
        logger = session.getLogger();
    }

    @Override
    public void init(@NonNull final ChannelSftp.Direction direction,
                     @NonNull final String src,
                     @NonNull final String dest,
                     final long max) {
        logger.log(Logger.INFO, () -> "Progress: direction=" + direction
                + ", src=" + src + ", dst=" + dest + ", max=" + max);
    }

    @Override
    public boolean count(final long count) {
        logger.log(Logger.INFO, () -> "Progress: count=" + count);
        return true;
    }

    @Override
    public void end() {
        logger.log(Logger.INFO, () -> "Progress: END");
    }
}
