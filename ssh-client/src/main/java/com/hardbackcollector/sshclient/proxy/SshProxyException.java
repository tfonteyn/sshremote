package com.hardbackcollector.sshclient.proxy;

import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.utils.SshException;

public class SshProxyException
        extends SshException {

    private static final long serialVersionUID = -5053690992921840875L;

    SshProxyException(@Nullable final String message) {
        super(message);
    }

    SshProxyException(@Nullable final String message,
                      @Nullable final Throwable e) {
        super(message, e);
    }
}
