package com.hardbackcollector.sshclient.forwarding;

import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.utils.SshException;

public class PortForwardException
        extends SshException {

    private static final long serialVersionUID = -1319309923966731989L;

    public PortForwardException(@Nullable final String message) {
        super(message);
    }

    PortForwardException(@Nullable final Throwable cause) {
        super(cause);
    }
}
