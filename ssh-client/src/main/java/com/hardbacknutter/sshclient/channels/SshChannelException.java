package com.hardbacknutter.sshclient.channels;

import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.utils.SshException;

public class SshChannelException
        extends SshException {

    private static final long serialVersionUID = -4830896425068724279L;

    public SshChannelException(@Nullable final String message) {
        super(message);
    }

    public SshChannelException(@Nullable final Throwable e) {
        super(e);
    }

    public SshChannelException(@Nullable final String message,
                               @Nullable final Throwable e) {
        super(message, e);
    }
}
