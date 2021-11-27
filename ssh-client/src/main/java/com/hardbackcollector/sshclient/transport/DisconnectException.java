package com.hardbackcollector.sshclient.transport;

import androidx.annotation.NonNull;

import java.io.IOException;

public class DisconnectException
        extends IOException {

    private static final long serialVersionUID = -3423896764936804226L;
    private final int reasonCode;

    DisconnectException(final int reasonCode,
                        @NonNull final String description) {
        super("SSH_MSG_DISCONNECT: " + reasonCode + " " + description);
        this.reasonCode = reasonCode;
    }

    public int getReasonCode() {
        return reasonCode;
    }
}
