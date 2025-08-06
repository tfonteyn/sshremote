package com.hardbacknutter.sshclient;

import com.hardbacknutter.sshclient.hostconfig.HostConfig;

import org.jspecify.annotations.Nullable;

public interface SshSessionConfig
        extends SshClientConfig {

    /**
     * Get the {@link HostConfig}.
     *
     * @return config
     */
    @Nullable
    HostConfig getHostConfig();
}
