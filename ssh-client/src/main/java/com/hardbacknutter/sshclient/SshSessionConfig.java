package com.hardbacknutter.sshclient;

import org.jspecify.annotations.Nullable;

import com.hardbacknutter.sshclient.hostconfig.HostConfig;

public interface SshSessionConfig extends SshClientConfig {

    @Nullable
    HostConfig getHostConfig();
}
