package com.hardbacknutter.sshclient.utils;

import androidx.annotation.Nullable;

/**
 * Base for all SSH Client related exceptions
 */
public class SshException
        extends Exception {

    private static final long serialVersionUID = -2314290899669414969L;

    protected SshException(@Nullable final String message) {
        super(message);
    }

    protected SshException(@Nullable final Throwable cause) {
        super(cause);
    }

    protected SshException(@Nullable final String message,
                           @Nullable final Throwable e) {
        super(message, e);
    }
}
