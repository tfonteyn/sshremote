package com.hardbacknutter.sshclient;

import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.hostconfig.HostConfig;

public interface SshSessionConfig extends SshClientConfig {

    @Nullable
    HostConfig getHostConfig();
}
