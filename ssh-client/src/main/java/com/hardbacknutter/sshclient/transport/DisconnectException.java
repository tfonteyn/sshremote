package com.hardbacknutter.sshclient.transport;

import java.io.IOException;

import com.hardbacknutter.sshclient.utils.SshConstants;

import org.jspecify.annotations.NonNull;

public class DisconnectException
        extends IOException {

    private static final long serialVersionUID = -3423896764936804226L;
    private final int reasonCode;

    /**
     * Constructor.
     *
     * @param reasonCode  from the {@link SshConstants#SSH_MSG_DISCONNECT} packet.
     * @param description from the packet.
     */
    DisconnectException(final int reasonCode,
                        @NonNull final String description) {
        super("SSH_MSG_DISCONNECT: " + reasonCode + " " + description);
        this.reasonCode = reasonCode;
    }

    /**
     * Get the reason code for the disconnect.
     *
     * @return the code from the {@link SshConstants#SSH_MSG_DISCONNECT} packet.
     */
    public int getReasonCode() {
        return reasonCode;
    }
}
