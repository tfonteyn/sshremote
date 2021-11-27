package com.hardbackcollector.sshclient.channels.session;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.ChannelSession;

class ChannelExitStatusImpl
        implements ChannelSession.ExitStatus {

    private final int status;
    @Nullable
    private final String message;
    @Nullable
    private final String signalName;
    private final boolean coreDumped;

    /**
     * Normal exit with a status.
     *
     * @param exitStatus from the process
     */
    ChannelExitStatusImpl(final int exitStatus) {
        this.status = exitStatus;
        this.message = null;
        this.coreDumped = false;
        this.signalName = null;
    }

    /**
     * Normal exit with a status and potentially a text message.
     *
     * @param exitStatus from the process
     */
    ChannelExitStatusImpl(final int exitStatus,
                          @Nullable final String message) {
        this.status = exitStatus;
        this.signalName = null;
        this.coreDumped = false;
        this.message = message;
    }

    /**
     * The process send a signal.
     */
    ChannelExitStatusImpl(@NonNull final String signalName,
                          final boolean coreDumped,
                          @Nullable final String message) {
        this.status = NO_EXIT_STATUS;
        this.signalName = signalName;
        this.coreDumped = coreDumped;
        this.message = message;
    }

    @Override
    public int getStatus() {
        return status;
    }

    @Override
    @Nullable
    public String getMessage() {
        return message;
    }

    @Override
    @Nullable
    public String getSignalName() {
        return signalName;
    }

    @Override
    public boolean isCoreDumped() {
        return coreDumped;
    }
}
