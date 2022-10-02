package com.hardbacknutter.sshclient.userauth;

import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.utils.SshException;

/**
 * Base class for all Authentication exceptions.
 */
public class SshAuthException
        extends SshException {

    private static final long serialVersionUID = -107825539663919324L;

    public SshAuthException(@Nullable final String message) {
        super(message);
    }

    public SshAuthException(@Nullable final Throwable cause) {
        super(cause);
    }
}
