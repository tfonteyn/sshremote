package com.hardbackcollector.sshclient.channels;

import androidx.annotation.Nullable;

public class SshChannelOpenException
        extends SshChannelException {

    private static final long serialVersionUID = 5788974613574147928L;

    private final int reasonCode;

    SshChannelOpenException(final int reasonCode,
                            @Nullable final String message) {
        super(message);
        this.reasonCode = reasonCode;
    }

    public int getReasonCode() {
        return reasonCode;
    }
}
