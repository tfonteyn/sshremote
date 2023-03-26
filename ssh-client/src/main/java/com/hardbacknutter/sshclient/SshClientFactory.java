package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.transport.SshClientImpl;

public final class SshClientFactory {

    private SshClientFactory() {
    }

    /**
     * Constructor.
     * <p>
     * The entry point for user-code.
     */
    @NonNull
    public static SshClient create() {
        return new SshClientImpl();
    }

    /**
     * Constructor.
     * <p>
     * The entry point for user-code.
     *
     * @param logger to use; can be {@code null} for no logging at all.
     */
    public static SshClient create(@Nullable final Logger logger) {
        return new SshClientImpl(logger);
    }
}
