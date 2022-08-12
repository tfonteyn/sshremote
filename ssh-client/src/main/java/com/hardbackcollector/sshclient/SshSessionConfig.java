package com.hardbackcollector.sshclient;

import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.hostconfig.HostConfig;

public interface SshSessionConfig extends SshClientConfig {

    @Nullable
    HostConfig getHostConfig();
}
